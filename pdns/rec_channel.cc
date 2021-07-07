#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "rec_channel.hh"
#include "utility.hh"
#include <sys/socket.h>
#include <cerrno>
#include "misc.hh"
#include <string.h>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <iostream>

#include "pdnsexception.hh"

#include "namespaces.hh"

std::atomic<bool> RecursorControlChannel::stop = false;

RecursorControlChannel::RecursorControlChannel()
{
  d_fd=-1;
  *d_local.sun_path=0;
  d_local.sun_family=0;
}

RecursorControlChannel::~RecursorControlChannel() 
{
  if(d_fd > 0)
    close(d_fd);
  if(*d_local.sun_path)
    unlink(d_local.sun_path);
}

static void setSocketBuffer(int fd, int optname, uint32_t size)
{
  uint32_t psize=0;
  socklen_t len=sizeof(psize);

  if (getsockopt(fd, SOL_SOCKET, optname, (void*)&psize, &len))
    throw PDNSException("Unable to getsocket buffer size: "+stringerror());

  if (psize > size)
    return;
  
  // failure to raise is not fatal
  (void)setsockopt(fd, SOL_SOCKET, optname, (const void*)&size, sizeof(size));
}


static void setSocketReceiveBuffer(int fd, uint32_t size)
{
  setSocketBuffer(fd, SO_RCVBUF, size);
}

static void setSocketSendBuffer(int fd, uint32_t size)
{
  setSocketBuffer(fd, SO_SNDBUF, size);
}

int RecursorControlChannel::listen(const string& fname)
{
  d_fd=socket(AF_UNIX,SOCK_DGRAM,0);
  setCloseOnExec(d_fd);

  if(d_fd < 0) 
    throw PDNSException("Creating UNIX domain socket: "+stringerror());
  
  int tmp=1;
  if(setsockopt(d_fd, SOL_SOCKET, SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0)
    throw PDNSException("Setsockopt failed: "+stringerror());
  
  int err=unlink(fname.c_str());
  if(err < 0 && errno!=ENOENT)
    throw PDNSException("Can't remove (previous) controlsocket '"+fname+"': "+stringerror() + " (try --socket-dir)");

  if(makeUNsockaddr(fname, &d_local))
    throw PDNSException("Unable to bind to controlsocket, path '"+fname+"' is not a valid UNIX socket path.");
    
  if(bind(d_fd, (sockaddr*)&d_local,sizeof(d_local))<0) 
    throw PDNSException("Unable to bind to controlsocket '"+fname+"': "+stringerror());

  // receive buf should be size of max datagram plus address size
  setSocketReceiveBuffer(d_fd, 60 * 1024);
  setSocketSendBuffer(d_fd, 64 * 1024);
  
  return d_fd;
}

void RecursorControlChannel::connect(const string& path, const string& fname)
{
  struct sockaddr_un remote;

  d_fd=socket(AF_UNIX,SOCK_DGRAM,0);
  setCloseOnExec(d_fd);

  if(d_fd < 0) 
    throw PDNSException("Creating UNIX domain socket: "+stringerror());

  try {
    int tmp=1;
    if(setsockopt(d_fd, SOL_SOCKET, SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0)
      throw PDNSException("Setsockopt failed: "+stringerror());
  
    string localname=path+"/lsockXXXXXX";
    *d_local.sun_path=0;
    if (makeUNsockaddr(localname, &d_local))
      throw PDNSException("Unable to bind to local temporary file, path '"+localname+"' is not a valid UNIX socket path.");

    if(mkstemp(d_local.sun_path) < 0)
      throw PDNSException("Unable to generate local temporary file in directory '"+path+"': "+stringerror());

    int err=unlink(d_local.sun_path);
    if(err < 0 && errno!=ENOENT)
      throw PDNSException("Unable to remove local controlsocket: "+stringerror());

    if(bind(d_fd, (sockaddr*)&d_local,sizeof(d_local))<0)
      throw PDNSException("Unable to bind to local temporary file: "+stringerror());

    if(chmod(d_local.sun_path,0666)<0) // make sure that pdns can reply!
      throw PDNSException("Unable to chmod local temporary socket: "+stringerror());

    string remotename=path+"/"+fname;
    if (makeUNsockaddr(remotename, &remote))
      throw PDNSException("Unable to connect to controlsocket, path '"+remotename+"' is not a valid UNIX socket path.");

    if(::connect(d_fd, (sockaddr*)&remote, sizeof(remote)) < 0) {
      if(*d_local.sun_path)
	unlink(d_local.sun_path);
      throw PDNSException("Unable to connect to remote '"+string(remote.sun_path)+"': "+stringerror());
    }

    // receive buf should be size of max datagram plus address size
    setSocketReceiveBuffer(d_fd, 60 * 1024);
    setSocketSendBuffer(d_fd, 64 * 1024);

  } catch (...) {
    close(d_fd);
    d_fd=-1;
    d_local.sun_path[0]=0;
    throw;
  }
}

static void sendfd(int s, int fd, const string* remote)
{
  struct msghdr    msg;
  struct cmsghdr  *cmsg;
  union {
    struct cmsghdr hdr;
    unsigned char    buf[CMSG_SPACE(sizeof(int))];
  } cmsgbuf;
  struct iovec io_vector[1];
  char ch = 'X';
 
  io_vector[0].iov_base = &ch;
  io_vector[0].iov_len = 1;

  memset(&msg, 0, sizeof(msg));
  if (remote) {
    msg.msg_name = const_cast<char*>(remote->c_str());
    msg.msg_namelen = remote->length();
  }
  msg.msg_control = &cmsgbuf.buf;
  msg.msg_controllen = sizeof(cmsgbuf.buf);
  msg.msg_iov = io_vector;
  msg.msg_iovlen = 1;

  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  *(int *)CMSG_DATA(cmsg) = fd;

  if (sendmsg(s, &msg, 0) == -1) {
    throw PDNSException("Unable to send fd message over control channel: "+stringerror());
  }
}

void RecursorControlChannel::send(const Answer& msg, const std::string* remote, unsigned int timeout, int fd)
{
  int ret = waitForRWData(d_fd, false, timeout, 0);
  if(ret == 0) {
    throw PDNSException("Timeout sending message over control channel");
  }
  else if(ret < 0) {
    throw PDNSException("Error sending message over control channel:" + stringerror());
  }

  if(remote) {
    struct sockaddr_un remoteaddr;
    memset(&remoteaddr, 0, sizeof(remoteaddr));
  
    remoteaddr.sun_family=AF_UNIX;
    strncpy(remoteaddr.sun_path, remote->c_str(), sizeof(remoteaddr.sun_path)-1);
    remoteaddr.sun_path[sizeof(remoteaddr.sun_path)-1] = '\0';

    if(::sendto(d_fd, &msg.d_ret, sizeof(msg.d_ret), 0, (struct sockaddr*) &remoteaddr, sizeof(remoteaddr) ) < 0)
      throw PDNSException("Unable to send message over control channel '"+string(remoteaddr.sun_path)+"': "+stringerror());
    if(::sendto(d_fd, msg.d_str.c_str(), msg.d_str.length(), 0, (struct sockaddr*) &remoteaddr, sizeof(remoteaddr) ) < 0)
      throw PDNSException("Unable to send message over control channel '"+string(remoteaddr.sun_path)+"': "+stringerror());
  }
  else {
    if(::send(d_fd, &msg.d_ret, sizeof(msg.d_ret), 0) < 0)
      throw PDNSException("Unable to send message over control channel: "+stringerror());
    if(::send(d_fd, msg.d_str.c_str(), msg.d_str.length(), 0) < 0)
      throw PDNSException("Unable to send message over control channel: "+stringerror());
  }
  if (fd != -1) {
    sendfd(d_fd, fd, remote);
  }
}

RecursorControlChannel::Answer RecursorControlChannel::recv(std::string* remote, unsigned int timeout)
{
  char buffer[16384];
  ssize_t len;
  struct sockaddr_un remoteaddr;
  socklen_t addrlen = sizeof(remoteaddr);

  int ret = waitForData(d_fd, timeout, 0);
  if (ret == 0) {
    throw PDNSException("Timeout waiting for answer from control channel");
  }
  int err;
  if (::recvfrom(d_fd, &err, sizeof(err), 0, (struct sockaddr*)&remoteaddr, &addrlen) != sizeof(err)) {
    throw PDNSException("Unable to receive return status over control channel1: " + stringerror());
  }
  if ((len = ::recvfrom(d_fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&remoteaddr, &addrlen)) < 0) {
    throw PDNSException("Unable to receive message over control channel2: "+stringerror());
  }

  if(remote) {
    *remote=remoteaddr.sun_path;
  }

  return {err, string(buffer, buffer + len)};
}

