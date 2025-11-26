#pragma once

#include "rr.hpp"

#include <oxen/quic/address.hpp>
#include <oxen/quic/loop.hpp>

#include <unordered_set>

struct ub_ctx;

namespace srouter
{
    class Router;
}

namespace srouter::dns
{

    namespace quic = oxen::quic;

    // TODO FIXME: Apple sys extension support.  See older commits (e.g. v0.9.14) where there is a
    // ConfigureAppleTrampoline with a bunch of comments about how it works and why it is needed
    // (basically: because libunbound is *inside* the extension and traffic generated from inside
    // does not go through the tunnel, so some hackery was summoned).

    class Unbound
    {
      public:
        Unbound(Router& router);

        ~Unbound();

        // Gives a query to unbound to resolve.  When the result comes back, on_result will be
        // called with the full DNS response from within the router loop (i.e. it is not necessary
        // to loop.call(...) inside the given callback).
        //
        // The `response` could be empty, in the case of an unbound failure to submit the query (and
        // can be called within the call to query()).
        void query(
            const std::string& name,
            RRType type,
            RRClass cls,
            std::function<void(std::span<const std::byte> response)> on_result);

      private:
        quic::Loop& _loop;

        struct ub_ctx_deleter
        {
            void operator()(ub_ctx* ctx);
        };
        std::unique_ptr<ub_ctx, ub_ctx_deleter> _ctx;

        struct active_query_state;

        // Holds the state for any in-progress queries: these are normally cleaned up in the
        // callback itself, but if we cancel all queries (i.e. when shutting down) we have to clean
        // up any outstanding ones manually.
        std::unordered_set<active_query_state*> _active_queries;
    };

}  // namespace srouter::dns
