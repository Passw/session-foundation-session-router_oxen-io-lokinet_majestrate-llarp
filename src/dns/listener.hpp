#pragma once

#include "dns/handler.hpp"

#include <oxen/quic/loop.hpp>
#include <oxen/quic/udp.hpp>

#include <list>
#include <memory>

struct evconnlistener;

namespace srouter
{
    class Router;
}
namespace srouter::dns
{
    namespace quic = oxen::quic;

    /// UDP+TCP listener for receiving and sending DNS requests.  This generally works with a
    /// dns::RequestHandler to actually generate the replies for a request, which then come back to
    /// this class to actually send the response to the network.
    class Listener
    {
        struct evconnlistener_deleter
        {
            void operator()(::evconnlistener* e);
        };

        struct udp_socket_helper;

        std::list<std::unique_ptr<udp_socket_helper>> _udp;
        std::list<std::unique_ptr<::evconnlistener, evconnlistener_deleter>> _tcp;

        // The object that handles processing of the actual request once we have extracted it from a
        // UDP packet or TCP stream:
        RequestHandler _handler;

      public:
        // Creates a TCP+UDP DNS listener that listens on `bind` for DNS requests.
        Listener(Router& router, const quic::Address& bind);

        // Adds another TCP+UDP listener on `bind`.  This is called implicitly during construction,
        // but can also be called if there is a need to listen on multiple addresses.
        void listen(quic::Loop& loop, const quic::Address& bind);

        // Set to the last port on which we set up a listener; this is mainly intended to be used
        // when listening on an address with a 0 port which will *actually* listen on a high random
        // port.
        uint16_t last_port;

        ~Listener();
    };

}  // namespace srouter::dns
