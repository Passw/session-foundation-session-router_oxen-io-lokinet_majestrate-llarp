#include "address/address.hpp"
#include "config/config.hpp"
#include "net/id.hpp"
#include "nodedb.hpp"
#include "router/router.hpp"
#include "session/session.hpp"
#include "util/logging.hpp"
#include "util/logging/buffer.hpp"

#include <oxenc/base32z.h>
#include <session/router.hpp>
#include <session/router_context.hpp>

#include <exception>
#include <future>
#include <memory>
#include <stdexcept>

using namespace std::literals;
namespace quic = oxen::quic;

static auto logcat = srouter::log::Cat("libsessionrouter");

namespace session::router
{
    namespace log = oxen::log;

    static auto make_embedded_context() { return std::make_unique<srouter::Context>(/*embedded=*/true); }

    SessionRouter::SessionRouter(std::string config, std::shared_ptr<oxen::quic::Loop> loop)
        : context{make_embedded_context()}
    {
        context->start(srouter::Config{srouter::config::Type::EmbeddedClient, std::move(config)}, loop);
    }

    SessionRouter::SessionRouter(path_ctor, const std::filesystem::path& config, std::shared_ptr<oxen::quic::Loop> loop)
        : context{make_embedded_context()}
    {
        ;
        context->start(srouter::Config{srouter::config::Type::EmbeddedClient, config}, loop);
    }

    SessionRouter::SessionRouter(Network n, std::shared_ptr<oxen::quic::Loop> loop) : context{make_embedded_context()}
    {
        srouter::Config conf{srouter::config::Type::EmbeddedClient};
        switch (n)
        {
            case Network::MAINNET:
                conf.router.net_id = srouter::NetID::MAINNET;
                break;
            case Network::TESTNET:
                conf.router.net_id = srouter::NetID::TESTNET;
                break;
            default:
                throw std::invalid_argument{"Unknown/unsupported network value passed to Session Router constructor"};
        }
        context->start(std::move(conf), loop);
    }

    SessionRouter::~SessionRouter()
    {
        context->stop();
        context->wait();
    }

    void SessionRouter::on_connected(std::function<void()> callback, bool persist)
    {
        context->router->on_connected(std::move(callback), persist);
    }

    void SessionRouter::on_disconnected(std::function<void()> callback, bool persist)
    {
        context->router->on_disconnected(std::move(callback), persist);
    }

    tunnel_info SessionRouter::establish_udp(
        std::string_view remote,
        uint16_t dest_port,
        std::function<void(tunnel_info)> on_established,
        std::function<void()> on_timeout)
    {
        // FIXME: check for valid ONS, and if so, we need to defer the lookup as well
        srouter::NetworkAddress netaddr;
        try
        {
            netaddr = srouter::NetworkAddress{remote};
        }
        catch (const std::exception& e)
        {
            throw std::invalid_argument{"Invalid remote address: {}"_format(e.what())};
        }

        if (dest_port == 0)
            throw std::invalid_argument{"Invalid remort port: port cannot be 0"};

        // log::info(logcat, "Creating session for udp connection to {}", netaddr);

        quic::Address src{"::1"s, 0};
        quic::Address dest{"::1"s, dest_port};

        auto [local_port, session] = context->router->session_endpoint().map_udp_remote_port(netaddr, dest_port);

        tunnel_info ti{
            .remote = netaddr.to_string(),
            .remote_port = dest_port,
            .local_port = local_port,
            // TODO FIXME: 1200 here is just a placeholder, we should be able to pick something better!
            .suggested_mtu = 1200};

        if (session->is_established())
        {
            if (on_established)
                on_established(ti);
        }
        else if (session->is_outbound)
        {
            if (on_established || on_timeout)
            {
                auto osession = std::static_pointer_cast<srouter::session::OutboundSession>(session);
                osession->on_established(
                    [ti, on_established, on_timeout](const srouter::session::OutboundSession& session) {
                        if (session.is_established())
                        {
                            if (on_established)
                                on_established(ti);
                        }
                        else
                        {
                            if (on_timeout)
                                on_timeout();
                        }
                    });
            }
        }
        else
        {
            log::warning(
                logcat, "Unexpected: tunnel session returned a non-established, but also non-outbound session!");
        }

        return ti;
    }

    void SessionRouter::close_udp(std::string_view remote, uint16_t port)
    {
        // FIXME: check for valid ONS, and if so, we need to defer the lookup as well
        srouter::NetworkAddress netaddr;
        try
        {
            netaddr = srouter::NetworkAddress{remote};
        }
        catch (const std::exception& e)
        {
            throw std::invalid_argument{"Invalid remote address: {}"_format(e.what())};
        }

        context->router->session_endpoint().unmap_udp_remote_port(netaddr, port);
    }

    std::optional<snode_path> SessionRouter::get_path_for_session(std::string_view remote)
    {
        srouter::NetworkAddress netaddr;
        try
        {
            netaddr = srouter::NetworkAddress{remote};
        }
        catch (const std::exception& e)
        {
            srouter::log::info(logcat, "Invalid remote address: {}", e.what());
            return std::nullopt;
        }

        return context->router->loop.call_get([&r = context->router, addr = std::move(netaddr)]() {
            std::optional<snode_path> ret;
            if (auto s = r->session_endpoint().get_session(addr); s)
            {
                ret = s->current_path();
            }
            return ret;
        });
    }

    std::vector<session_path> SessionRouter::get_all_session_paths()
    {
        return context->router->loop.call_get([&r = context->router]() {
            std::vector<session_path> ret;
            auto f = [&ret](const srouter::NetworkAddress& addr, const srouter::session::Session& s) {
                ret.emplace_back(s.current_path(), addr.to_string());
            };
            return ret;
        });
    }

}  // namespace session::router
