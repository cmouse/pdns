#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "namespaces.hh"
#include "misc.hh"
#include "dolog.hh"

#include <string>
#include <unistd.h>
#include <errno.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/time.h>
#include <sys/types.h>

#ifndef HAVE_RTNETLINK

int dnsdist_open_netlink(void) {
  return -1;
}

int dnsdist_should_reopen(int sock, bool &reopen_r) {
  reopen_r = false;
  return 0;
}

#else

int dnsdist_open_netlink(void) {
  struct sockaddr_nl addr;

  int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock < 0) {
    errlog("Cannot open NETLINK socket: %s", stringerror());
    return -1;
  }
 
  memset(&addr, 0, sizeof(addr));

  addr.nl_family = AF_NETLINK;
  addr.nl_pid = getpid();
  addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
                   RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;

   if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
     errlog("Cannot open NETLINK socket: %s", stringerror());
     return -1;
   }

   return sock;
}

int dnsdist_should_reopen(int sock, bool &reopen_r) {
  int status;
  unsigned char buf[4096];
  struct iovec iov = {buf, sizeof buf};
  struct sockaddr_nl snl;
  struct msghdr msg = {(void *)&snl, sizeof snl, &iov, 1, NULL, 0, 0};
  struct nlmsghdr *h;

  reopen_r = false;
  for(;;) {
    status = recvmsg(sock, &msg, MSG_DONTWAIT);

    if (status < 0) {
      if (errno == EWOULDBLOCK || errno == EAGAIN)
        return status;

      errlog("Cannot read NETLINK socket: %s", stringerror());
      return status;
    } else if (status == 0) {
      /* EOF */
      return status;
    }

    /* just consume the socket */
    if (reopen_r)
      continue;

    h = (struct nlmsghdr *)buf;
    while(NLMSG_OK(h, status)) {
      if (h->nlmsg_type == NLMSG_DONE)
        break;
      vinfolog("parsing netlink message, type=%u, len=%u, flags=%u", h->nlmsg_type, h->nlmsg_len, h->nlmsg_flags);

      if (h->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
        errlog("Cannot read NETLINK socket: err=%d, seq=%u", err->error, err->msg.nlmsg_seq);
        return -1;
      } else if (h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK) {
        vinfolog("netlink detected interface change");
        reopen_r = true;
        break;
      } else if (h->nlmsg_type == RTM_NEWROUTE || h->nlmsg_type == RTM_DELROUTE ||
                 h->nlmsg_type == RTM_NEWRULE || h->nlmsg_type == RTM_DELRULE) {
        vinfolog("netlink detected routing change");
        reopen_r = true;
        break;
      }
      h = NLMSG_NEXT(h, status);
    }
  }

  return 1;
}

#endif
