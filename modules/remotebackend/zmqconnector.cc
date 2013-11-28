#include "remotebackend.hh"
#ifdef REMOTEBACKEND_ZEROMQ

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <boost/foreach.hpp>
#include <sstream>
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

ZeroMQConnector::ZeroMQConnector(std::map<std::string,std::string> options) : d_ctx(1), d_sock(d_ctx, ZMQ_REQ)  {
  // lookup timeout, target and stuff
  if (options.count("endpoint") == 0) {
    L<<Logger::Error<<"Cannot find 'endpoint' option in connection string"<<endl;
    throw new PDNSException("Cannot find 'endpoint' option in connection string");
  }
  this->d_endpoint = options.find("endpoint")->second;
  this->d_options = options;
  this->d_timeout=2000;

  if (options.find("timeout") != options.end()) {
     this->d_timeout = boost::lexical_cast<int>(options.find("timeout")->second);
  }

  d_sock.connect(d_endpoint.c_str());
};

ZeroMQConnector::~ZeroMQConnector() {
};

int ZeroMQConnector::send_message(const rapidjson::Document &input) {
   std::string line;
   line = makeStringFromDocument(input);
   zmq::message_t message(line.size()+1);   
   line.copy(reinterpret_cast<char*>(message.data()), line.size());
   reinterpret_cast<char*>(message.data())[line.size()]=0;

   try {
     if (d_sock.send(message, 0) == false) {
         // message was not sent
         L<<Logger::Error<<"Cannot send to " << this->d_endpoint << ": " << errno;
         return 0;
     }
     // do a really fast poll here, otherwise the message is not sent
     zmq_pollitem_t item;
     item.socket = d_sock;
     item.events = ZMQ_POLLOUT;
     zmq::poll(&item, 1, 500);
   } catch (std::exception &ex) {
     L<<Logger::Error<<"Cannot send to " << this->d_endpoint << ": " << ex.what();
     throw new PDNSException(ex.what());
   }

   return line.size();
}

int ZeroMQConnector::recv_message(rapidjson::Document &output) {
   int rv = 0;
   // try to receive message
   zmq_pollitem_t item;
   rapidjson::GenericReader<rapidjson::UTF8<> , rapidjson::MemoryPoolAllocator<> > r;
   zmq::message_t message;

   item.socket = d_sock;
   item.events = ZMQ_POLLIN;

   try {
     // do zmq::poll few times
     for(int loops = 0; loops < d_timeout; loops++) {
       if (zmq::poll(&item, 1, 1000)>0) {
         // we have an event
         if ((item.revents & ZMQ_POLLIN) == ZMQ_POLLIN) {
           char *data;
           // read something
             if (d_sock.recv(&message, 0) && message.size() > 0) {
               data = new char[message.size()+1];
               // convert it into json
               memcpy(data, message.data(), message.size());
               data[message.size()]=0;
               rapidjson::StringStream ss(data);
               output.ParseStream<0>(ss);
               delete [] data;
               if (output.HasParseError() == false)
                 rv = message.size();
               else 
                 L<<Logger::Error<<"Cannot parse JSON reply from " << this->d_endpoint;
               break;
             } else if (errno == EAGAIN) { continue; // try again }
             } else {
                break; 
             } 
          }
        }
     }
   } catch (std::exception &ex) {
     L<<Logger::Error<<"Cannot receive from " << this->d_endpoint << ": " << ex.what();
     throw new PDNSException(ex.what());
   }

   return rv;
}

#endif
