#include "router/rpc_backend.hpp"

#include "consensus/reachability_testing.hpp"
#include "rpc/oxend_rpc.hpp"
#include "rpc/rpc_server.hpp"

#include <oxenmq/oxenmq.h>

#include <memory>

namespace srouter::full
{
    namespace
    {
        std::shared_ptr<oxenmq::OxenMQ> make_omq()
        {
            auto omq = std::make_shared<oxenmq::OxenMQ>();
            // Raise the max message size (no limit) so that syncing the registered relay list from
            // oxend -- which can exceed the default 1MB -- doesn't get the connection closed.
            omq->MAX_MSG_SIZE = -1;
            return omq;
        }

        void start_omq(oxenmq::OxenMQ& omq) { omq.start(); }

        std::shared_ptr<rpc::IOxendClient> make_oxend(Router& r, oxenmq::OxenMQ& omq)
        {
            return std::make_shared<rpc::OxendRPC>(omq, r);
        }

        std::shared_ptr<rpc::RPCServer> make_rpc_server(Router& r, oxenmq::OxenMQ& omq)
        {
            return std::make_shared<rpc::RPCServer>(omq, r);
        }

        std::shared_ptr<consensus::IReachability> make_reachability(Router& r)
        {
            return std::make_shared<consensus::reachability_testing>(r);
        }

        const RpcBackendHooks hooks{
            .make_omq = &make_omq,
            .start_omq = &start_omq,
            .make_oxend = &make_oxend,
            .make_rpc_server = &make_rpc_server,
            .make_reachability = &make_reachability,
        };
    }  // namespace

    void install_rpc_backend() { rpc_backend = &hooks; }

}  // namespace srouter::full
