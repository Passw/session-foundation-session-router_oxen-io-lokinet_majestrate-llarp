#include "address/address.hpp"
#include "config/config.hpp"
#include "link/endpoint.hpp"
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

    SessionRouter::SessionRouter(std::string config, std::shared_ptr<oxen::quic::Loop> loop)
        : context{std::make_unique<srouter::Context>(
              /*embedded=*/true, srouter::Config{srouter::config::Type::EmbeddedClient, std::move(config)}, loop)}
    {}

    SessionRouter::SessionRouter(path_ctor, const std::filesystem::path& config, std::shared_ptr<oxen::quic::Loop> loop)
        : context{std::make_unique<srouter::Context>(
              /*embedded=*/true, srouter::Config{srouter::config::Type::EmbeddedClient, config}, loop)}
    {}

    SessionRouter::SessionRouter(Network n, std::shared_ptr<oxen::quic::Loop> loop)
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
        context = std::make_unique<srouter::Context>(/*embedded-*/ true, std::move(conf), loop);
    }

    SessionRouter::~SessionRouter() {}

    void SessionRouter::on_connected(std::function<void()> callback, bool with_path, bool persist)
    {
        context->router->on_connected(std::move(callback), with_path, persist);
    }

    void SessionRouter::on_disconnected(std::function<void()> callback, bool with_path, bool persist)
    {
        context->router->on_disconnected(std::move(callback), with_path, persist);
    }

    std::optional<tunnel_info> SessionRouter::establish_udp(
        std::string_view remote,
        uint16_t dest_port,
        std::function<void(tunnel_info)> on_established,
        std::function<void()> on_timeout)
    {
        if (srouter::is_valid_sns(remote))
            throw std::invalid_argument{"establish_udp requires a network pubkey address, not an ONS/SNS addresses"};

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

        auto mapped = context->router->session_endpoint().map_udp_remote_port(netaddr, dest_port);
        if (!mapped)
            return std::nullopt;

        auto& [local_port, session] = *mapped;

        // Total tunnel overhead from outer UDP payload to inner payload:
        // outer QUIC packet framing (44) + path onion (41) + session encryption (37)
        // + IPv6+UDP wrapping (48) = 170 bytes.
        constexpr size_t TUNNEL_OVERHEAD = 170;

        // If the outer endpoint has a max UDP payload cap, we can compute the suggested inner
        // payload size.  Otherwise (uncapped PMTUD), suggested_mtu is nullopt.
        std::optional<uint16_t> suggested_mtu;
        if (auto outer_max = context->router->link_endpoint().get_max_udp_payload();
            outer_max && *outer_max > TUNNEL_OVERHEAD)
            suggested_mtu = *outer_max - TUNNEL_OVERHEAD;

        tunnel_info ti{
            .remote = netaddr.to_string(),
            .remote_port = dest_port,
            .local_port = local_port,
            .suggested_mtu = suggested_mtu};

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

    static snode_path to_snode_path(const srouter::path::Path::Info& info)
    {
        snode_path path;
        for (const auto& [rid, ip] : info.relays)
            path.emplace_back(srouter::NetworkAddress{rid, false}.to_string(), ip.to_string());
        return path;
    }

    void SessionRouter::resolve(
        std::string address, std::function<void(std::optional<std::string> addr, bool timeout)> callback)
    {
        if (!srouter::is_valid_sns(address))
        {
            try
            {
                srouter::NetworkAddress{address};
            }
            catch (...)
            {
                throw std::invalid_argument{
                    "Invalid address: '{}' is not a valid SNS nor a valid network pubkey address"_format(address)};
            }
            callback(std::move(address), false);
            return;
        }

        context->router->_jq->call([address = std::move(address),
                                    callback = std::move(callback),
                                    &ep = context->router->session_endpoint()]() mutable {
            ep.resolve_sns(
                std::move(address),
                [callback = std::move(callback)](
                    std::optional<srouter::NetworkAddress> netaddr, bool assertive, std::chrono::milliseconds /*ttl*/) {
                    std::optional<std::string> a;
                    if (netaddr)
                        a = netaddr->to_string();
                    callback(std::move(a), !assertive);
                });
        });
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

        return context->router->_jq->call_get([&r = context->router, addr = std::move(netaddr)]() {
            std::optional<snode_path> ret;
            if (auto* s = r->session_endpoint().get_session(addr))
                ret = to_snode_path(s->current_path_info());
            return ret;
        });
    }

    std::vector<session_path> SessionRouter::get_all_session_paths()
    {
        return context->router->_jq->call_get([&r = context->router]() {
            std::vector<session_path> ret;
            r->session_endpoint().for_each_session(
                [&ret](const srouter::NetworkAddress& addr, const srouter::session::Session& s) {
                    ret.emplace_back(to_snode_path(s.current_path_info()), addr.to_string());
                });
            return ret;
        });
    }

}  // namespace session::router
