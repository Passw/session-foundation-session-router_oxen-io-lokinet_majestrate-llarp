#include "tun.hpp"

#include <oxen/log.hpp>
#include <oxenc/base32z.h>
#include <oxenc/endian.h>

#include <span>
#include <variant>
#ifndef _WIN32
#include <sys/socket.h>
#endif

#include "auth/auth.hpp"
#include "constants/platform.hpp"
#include "contact/sns.hpp"
#include "dns/dns.hpp"
#include "dns/encode.hpp"
#include "nodedb.hpp"
#include "router/route_poker.hpp"
#include "router/router.hpp"
#include "util/logging/buffer.hpp"
#include "util/str.hpp"

#include <nlohmann/json.hpp>

namespace srouter::handlers
{
    static auto logcat = log::Cat("tun");

    bool TunEndpoint::maybe_hook_dns(
        const std::shared_ptr<dns::PacketSource>& source,
        const dns::Message& query,
        const quic::Address& to,
        const quic::Address& from)
    {
        if (not should_hook_dns_message(query))
            return false;

        auto job = std::make_shared<dns::QueryJob>(source, query.clone(), to, from);
        if (!handle_hooked_dns_message(query.clone(), [job](dns::Message msg) { job->send_reply(msg.encode()); }))
            job->cancel();
        return true;
    }

    /// Intercepts DNS IP packets on platforms where binding to a low port isn't viable.
    /// (windows/macos/ios/android ... aka everything that is not linux... funny that)
    class DnsInterceptor : public dns::PacketSource
    {
        ip_pkt_hook _hook;
        quic::Address _our_ip;  // maybe should be an IP type...?
        srouter::DnsConfig _config;

      public:
        explicit DnsInterceptor(ip_pkt_hook reply, quic::Address our_ip, srouter::DnsConfig conf)
            : _hook{std::move(reply)}, _our_ip{std::move(our_ip)}, _config{std::move(conf)}
        {}

        ~DnsInterceptor() override = default;

        void send_udp(
            const quic::Address& to, const quic::Address& from, std::span<const std::byte> payload) const override
        {
            log::critical(logcat, "DNS interceptor FIXME!");
            if (payload.empty())
                return;
            // FIXME: this
            (void)to;
            (void)from;
            (void)payload;
            // _hook(data.make_udp(to, from));
        }

        std::optional<quic::Address> bound_on() const override { return std::nullopt; }

        bool would_loop(const quic::Address& to, const quic::Address& from) const override
        {
            if constexpr (platform::is_apple)
            {
                // DNS on Apple is a bit weird because in order for the NetworkExtension itself to
                // send data through the tunnel we have to proxy DNS requests through Apple APIs
                // (and so our actual upstream DNS won't be set in our resolvers, which is why the
                // vanilla WouldLoop won't work for us).  However when active the mac also only
                // queries the main tunnel IP for DNS, so we consider anything else to be
                // upstream-bound DNS to let it through the tunnel.
                return to != _our_ip;
            }
            else if (auto maybe_addr = _config._query_bind)
            {
                const auto& addr = *maybe_addr;
                // omit traffic to and from our dns socket
                return addr == to or addr == from;
            }
            return false;
        }
    };

    class TunDNS : public dns::Server
    {
        const TunEndpoint* _tun;
        std::optional<quic::Address> _query_bind;
        quic::Address _our_ip;

      public:
        std::shared_ptr<dns::PacketSource> pkt_source;

        ~TunDNS() override = default;

        explicit TunDNS(TunEndpoint* ep, const srouter::DnsConfig& conf)
            : dns::Server{ep->router().loop, conf, 0},
              _tun{ep},
              _query_bind{conf._query_bind},
              _our_ip{ep->get_ipv4()}  // FIXME: What about IPv6?
        {
            if (_query_bind)
                _our_ip.set_port(_query_bind->port());
        }

        std::shared_ptr<dns::PacketSource> make_packet_source_on(
            const quic::Address&, const srouter::DnsConfig& conf) override
        {
            (void)_tun;
            auto ptr = std::make_shared<DnsInterceptor>(
                [](IPPacket pkt) {
                    (void)pkt;
                    // ep->handle_write_ip_packet(pkt.ConstBuffer(), pkt.srcv6(), pkt.dstv6(), 0);
                },
                _our_ip,
                conf);
            pkt_source = ptr;
            return ptr;
        }
    };

    // NB: It looks like this could/should be called during the constructor,
    // but as it passes weak_from_this to the dns server, it has to be after.
    void TunEndpoint::setup_dns()
    {
        log::debug(logcat, "{} setting up DNS...", name());

        auto& dns_config = _router.config().dns;
        const auto& info = get_vpn_interface()->interface_info();

        if (dns_config.l3_intercept)
        {
            // FIXME: this entire if block is so broken...
            _dns = std::make_unique<TunDNS>(this, dns_config);
            auto* dns = static_cast<TunDNS*>(_dns.get());

            uint16_t p = 53;

            while (p < 100)
            {
                try
                {
                    _packet_router->add_udp_handler(p, [this, dns](IPPacket pkt) {
                        // TODO FIXME
                        log::critical(logcat, "TODO FIXME: L3 udp interceptor!");
                        // if (dns->maybe_handle_payload(dns->pkt_source, pkt.destination(), pkt.source(),
                        // pkt.udp_data()))
                        //     return;

                        handle_outbound_packet(std::move(pkt));
                    });
                }
                catch (const std::exception& e)
                {
                    if (p += 1; p >= 100)
                        throw std::runtime_error{"Failed to port map udp handler: {}"_format(e.what())};
                }
            }
        }
        else
            _dns = std::make_unique<dns::Server>(_router.loop, dns_config, info.index);

        _dns->add_resolver(weak_from_this());
        _dns->start();

        if (dns_config.l3_intercept)
        {
            if (auto vpn = _router.vpn_platform())
            {
                // get the first local address we know of
                std::optional<quic::Address> localaddr;

                for (auto res : _dns->get_all_resolvers())
                {
                    if (auto ptr = res.lock())
                    {
                        localaddr = ptr->get_local_addr();

                        if (localaddr)
                            break;
                    }
                }
                if (platform::is_windows)
                {
                    // auto dns_io = vpn->create_packet_io(0, localaddr);
                    // router().loop()->add_ticker([dns_io, handler = m_PacketRouter]() {
                    //   net::IPPacket pkt = dns_io->ReadNextPacket();
                    //   while (not pkt.empty())
                    //   {
                    //     handler->HandleIPPacket(std::move(pkt));
                    //     pkt = dns_io->ReadNextPacket();
                    //   }
                    // });
                    // m_RawDNS = dns_io;
                }

                (void)vpn;
            }

            if (_raw_DNS)
                _raw_DNS->Start();
        }
    }

    void TunEndpoint::reconfigure_dns(std::vector<quic::Address> servers)
    {
        if (_dns)
        {
            for (auto weak : _dns->get_all_resolvers())
            {
                if (auto ptr = weak.lock())
                    ptr->reset_resolver(servers);
            }
        }
    }

    TunEndpoint::TunEndpoint(Router& r) : _router{r}
    {
        _packet_router =
            std::make_shared<vpn::PacketRouter>([this](IPPacket pkt) { handle_outbound_packet(std::move(pkt)); });

        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        auto& net_conf = _router.config().network;

        _exit_policy = net_conf.traffic_policy;

        _if_name = net_conf._if_name.value_or("");

        // These should have been assigned by Router before this:
        assert(net_conf._local_ip_net);
        assert(net_conf._local_ipv6_net);

        _local_net = *net_conf._local_ip_net;
        _local_ipv6_net = *net_conf._local_ipv6_net;

#if 0
        if (net_conf.addr_map_persist_file)
        {
            _persisting_addr_file = net_conf.addr_map_persist_file;
            persist_addrs = true;
        }
#endif

        NetworkAddress me{_router.id(), !_router.is_service_node};
        _local_ipv4_mapping.insert(_local_net.ip, me);
        _local_ipv6_mapping.insert(_local_ipv6_net.ip, std::move(me));

        auto add_mappings = [](const auto& local_net, auto& mapping, const auto& reserved) {
            for (auto& [remote, local] : reserved)
            {
                if (!local_net.contains(local))
                {
                    log::error(
                        logcat,
                        "Unable to apply {} <-> {} IP mapping: that IP is not inside the local network range {}",
                        remote,
                        local,
                        local_net);
                    continue;
                }
                if (mapping.contains(remote))
                {
                    log::error(
                        logcat, "Unable to apply {} <-> {} IP mapping: that remote is already assigned", remote, local);
                    continue;
                }
                if (mapping.contains(local))
                {
                    log::error(
                        logcat, "Unable to apply {} <-> {} IP mapping: that IP is already assigned", local, remote);
                    continue;
                }
                mapping.insert(local, remote);
            }
        };
        add_mappings(_local_net, _local_ipv4_mapping, net_conf._reserved_local_ipv4);
        add_mappings(_local_ipv6_net, _local_ipv6_mapping, net_conf._reserved_local_ipv6);

        log::debug(logcat, "Tun constructing IPRange iterator on local networks: {}, {}", _local_net, _local_ipv6_net);
        _local_range_iterator = IPRangeIterator{_local_net};
        _local_ipv6_range_iterator = IPv6RangeIterator{_local_ipv6_net};

        vpn::InterfaceInfo info;
        info.ifname = _if_name;
        info.addrs.emplace_back(_local_net);
        info.addrs.emplace_back(_local_ipv6_net);

        log::debug(logcat, "{} setting up network...", name());

        log::info(logcat, "{} using IPv4 address range {}", name(), _local_net);
        log::info(logcat, "{} using IPv6 address range {}", name(), _local_ipv6_net);

        _net_if = router().vpn_platform()->create_interface(std::move(info), &_router);
        _if_name = _net_if->interface_info().ifname;

        log::info(logcat, "{} got network interface:{}", name(), _if_name);
    }

    static const auto localhost_ctld = "localhost.{}"_format(CLIENT_TLD);
    static const auto dot_localhost_ctld = ".localhost.{}"_format(CLIENT_TLD);
    static bool is_localhost(std::string_view qname)
    {
        return qname == "localhost.loki" or qname.ends_with(".localhost.loki") or qname == localhost_ctld
            or qname.ends_with(dot_localhost_ctld);
    }

    static std::optional<RouterID> parse_rid(std::string_view b32rid)
    {
        auto rid = std::make_optional<RouterID>();
        if (not rid->from_base32z(b32rid))
            rid.reset();
        return rid;
    }

    static std::optional<RouterID> is_snode(std::string_view name)
    {
        if (name.ends_with(RELAY_DOT_TLD))
            name.remove_suffix(RELAY_DOT_TLD.size());
        else
            return std::nullopt;
        return parse_rid(name);
    }

    static dns::Message& clear_dns_message(dns::Message& msg)
    {
        // msg.authorities.clear();
        // msg.additional.clear();
        msg.answers.clear();
        msg.hdr_fields &= ~dns::flags_RCODENxDomain;
        return msg;
    }

    template <typename T, typename... Args>
    static std::optional<T> try_making(Args&&... args)
    {
        try
        {
            return std::make_optional<T>(std::forward<Args>(args)...);
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

    static const auto random_snode = "random.{}"_format(RELAY_TLD);

    bool TunEndpoint::handle_hooked_dns_message(
        dns::Message msg, std::function<void(dns::Message)> reply, std::optional<std::string> qname_override)
    {
        log::trace(logcat, "handle_hooked_dns_message");
        if (msg.questions.size() != 1)
        {
            log::warning(logcat, "bad number of dns questions: {}", msg.questions.size());
            return false;
        }

        auto& q = msg.questions[0];

        std::string qname;
        if (qname_override)
            qname = std::move(*qname_override);
        else
            qname = q.name();
        std::string hostname, tld;
        std::vector<std::string> sub;
        {
            auto nameparts = split(qname, ".");
            if (nameparts.size() < 2)
            {
                log::warning(logcat, "bad DNS request, no TLD or hostname: {}", qname);
                return false;
            }
            hostname = nameparts[nameparts.size() - 2];
            tld = nameparts.back();
            sub.reserve(nameparts.size() - 2);
            for (auto s : std::views::take(nameparts, static_cast<int>(nameparts.size()) - 2))
                sub.emplace_back(s);
        }
        bool localhost = is_localhost(qname);

        // localhost.sesh/localhost.loki is always a CNAME to our own pubkey, regardless of the
        // question type.
        if (localhost)
        {
            auto our_hostname = _router.id().to_string();
            auto our_tld = _router.is_service_node ? RELAY_TLD : CLIENT_TLD;
            auto our_name = "{}.{}"_format(our_hostname, our_tld);

            if (tld == "loki")
            {
                // first: report a cname for the deprecated localhost.loki -> localhost.sesh

                msg.set_rr_name("localhost.loki");
                msg.add_cname_reply("localhost.{}"_format(our_tld));
            }
            // report CNAME: localhost.sesh -> pubkey.sesh
            msg.set_rr_name("localhost.{}"_format(our_tld));
            msg.add_cname_reply(our_name);

            if (q.qtype == dns::RRType::CNAME)
            {
                // If we were queried specifically for a cname, then we are done.
                reply(std::move(msg));
                return true;
            }

            // Otherwise we continue processing to be able to return supplemental records through
            // the cname, so that if you request "foo.localhost.loki" we end up returning:
            // localhost.loki CNAME for localhost.sesh
            // localhost.sesh CNAME for PUBKEY.sesh
            // foo.PUBKEY.sesh IN X VALUE (or whatever)
            // And so for for the rest of the answer processing that we were given PUBKEY.sesh,
            // rather than localhost.loki/.sesh:
            qname = sub.empty() ? our_name : "{}.{}"_format(fmt::join(sub, "."), our_name);
            msg.set_rr_name(qname);

            tld = our_tld;
            hostname = std::move(our_hostname);
        }
        else if (qname == random_snode)
        {
            // Similar to the localhost case: we first return a CNAME of random.snode ->
            // SOMEPK.snode, then continue processing as if that was what you asked for.

            if (auto* rc = _router.node_db().get_random_rc())
            {
                hostname = rc->router_id().to_string();
                qname = "{}.{}"_format(hostname, RELAY_TLD);
                msg.add_cname_reply(qname, 1s);
                if (q.qtype == dns::RRType::CNAME)
                {
                    reply(std::move(msg));
                    return true;
                }

                msg.set_rr_name(qname);
            }
            else
            {
                msg.set_nx_reply();
                reply(std::move(msg));
                return true;
            }
        }
        else if (tld == "loki" && hostname.size() != oxenc::to_base32z_size(RouterID::SIZE))
        {
            // ONS lookup: initiate a lookup and, when we get the response, set up a CNAME of
            // NAME.loki -> PUBKEY.sesh, then recurse to process other parts of the request (such as
            // mapping to a AAAA).

            // TODO: .sesh SNS resolution, once implemented

            // ONS lookup:
            auto lookup = "{}.loki"_format(hostname);
            _router.session_endpoint().resolve_sns(
                lookup,
                [this,
                 lookup,
                 sub = std::move(sub),
                 reply = std::move(reply),
                 msg_ptr = std::make_shared<dns::Message>(std::move(msg)),
                 cname_only = q.qtype == dns::RRType::CNAME](
                    std::optional<NetworkAddress> maybe_netaddr,
                    bool assertive,
                    std::chrono::milliseconds ttl) mutable {
                    auto& msg = *msg_ptr;
                    msg.set_rr_name(lookup);
                    if (maybe_netaddr)
                    {
                        auto target = maybe_netaddr->to_string();
                        msg.add_cname_reply(target);
                        if (cname_only)
                            return;
                        auto qname = sub.empty() ? target : "{}.{}"_format(fmt::join(sub, "."), target);
                        msg.set_rr_name(qname);
                        handle_hooked_dns_message(std::move(msg), std::move(reply), std::move(qname));
                        return;
                    }

                    if (assertive)
                    {
                        // We got an assertive "does not exist" message (and not just a failure
                        // or timeout), so add the nx reply
                        msg.set_nx_reply();
                        // FIXME: we should be able to provide a TTL here
                    }
                    else
                    {
                        // We failed to get a response at all so just NX with a short timeout so
                        // that they will try again soon to resolve it.  (We don't want to
                        // SERVFAIL here because that could make the resolver try another DNS
                        // server).
                        assert(!assertive);
                        // FIXME: should be able to specify a TTL here
                        msg.set_nx_reply();
                    }
                    reply(std::move(msg));
                });
            return true;
        }

        if (q.qtype == dns::RRType::TXT)
        {
            // TXT records can be used to query some basic info:

            // TXT on MYPUBKEY.sesh returns the basic version and netid:
            if (localhost && sub.empty())
                msg.add_txt_reply("sessionrouter={} v={} netid={}"_format(
                    _router.is_service_node ? "relay" : "client", fmt::join(VERSION, "."), _router.netid()));

            // TXT on PUBKEY.snode gives back some basic RC info (if we have the RC)
            else if (auto rid = is_snode(qname))
            {
                if (auto* rc = _router.node_db().get_rc(*rid))
                {
                    msg.add_txt_reply("rc v={} a={} t={}"_format(
                        fmt::join(rc->version(), "."), rc->addr(), rc->timestamp().time_since_epoch().count()));
                }
                else
                    msg.set_nx_reply();
            }
            else
                msg.set_nx_reply();
            reply(std::move(msg));
            return true;
        }

        // "Regular" A or AAAA lookups
        if (bool aaaa = q.qtype == dns::RRType::AAAA; aaaa || q.qtype == dns::RRType::A)
        {
            // Attempt to parse a "pubkey.snode" or "pubkey.sesh":
            if (auto maybe_netaddr = try_making<NetworkAddress>("{}.{}"_format(hostname, tld)))
            {
                // DNS lookup implies we want a session, so make one (NOP if we have one)
                // This also means if we don't use that session the IP mapping will release when
                // it expires, which it wouldn't otherwise without a tedious periodic check.
                bool created_session = false;
                try
                {
                    created_session = (bool)_router.session_endpoint().initiate_remote_session(*maybe_netaddr, nullptr);
                }
                catch (const std::exception& e)
                {
                    log::warning(logcat, "Failed to initiate remote session to {}: {}", *maybe_netaddr, e.what());
                }
                if (created_session)
                {
                    if (aaaa)
                        msg.add_reply(map6(*maybe_netaddr));
                    else if (!sub.empty() && sub.back() == "ipv4"sv)
                    {
                        // We don't map IPv4 addresses by default, but it is still possible to get
                        // one by requesting ipv4.somepubkey.sesh/snode (or a subdomain thereof).
                        if (auto v4_addr = map4(*maybe_netaddr); v4_addr)
                            msg.add_reply(*v4_addr);
                        else
                            log::warning(logcat, "IPv4 mapping requested for {} failed.", *maybe_netaddr);
                    }
                    // else they requested A *not* using the magic ipv4 subdomain, so we only have
                    // AAAA to offer and thus we return a reply without an answer record (which is
                    // the proper DNS way to say "something exists at this address, but not with the
                    // type you requested requested", as opposed to this nx_reply below, which means
                    // "this record does not exist").
                }
                else
                    msg.set_nx_reply();
                reply(std::move(msg));

                return true;
            }

            // Otherwise it's some query type we don't support, so return does-not-exist.
            msg.set_nx_reply();
            reply(std::move(msg));
            return true;
        }

        // Reverse DNS lookups:
        if (q.qtype == dns::RRType::PTR)
        {
            // reverse dns
            bool found = false;
            if (auto ip = dns::decode_ptr(q.qname))
                std::visit(
                    [&](const auto& ip) {
                        if (auto addr = _lookup_mapped_ip(ip))
                        {
                            msg.add_ptr_reply(addr->to_string());
                            found = true;
                        }
                    },
                    *ip);

            if (!found)
                msg.set_nx_reply();

            reply(std::move(msg));
            return true;
        }

        if (q.qtype == dns::RRType::SRV && (tld == CLIENT_TLD || tld == "loki") && sub.size() == 2
            && sub[0].starts_with('_') && sub[1].starts_with('_'))
        {
            if (auto rid = parse_rid(hostname))
            {
                _router.session_endpoint().lookup_client_intro(
                    *rid,
                    [msg = std::make_shared<dns::Message>(std::move(msg)), sub, reply = std::move(reply)](
                        const std::optional<ClientContact>& cc) mutable {
                        if (cc)
                        {
                            for (const auto& srv : cc->SRVs())
                                if (srv.service == sub[0] && srv.proto == sub[1])
                                    msg->add_reply(srv);
                        }
                        else
                            msg->set_nx_reply();

                        reply(std::move(*msg));
                    });
                return true;
            }
        }

        msg.set_nx_reply();
        reply(std::move(msg));
        return true;
    }

    bool TunEndpoint::should_hook_dns_message(const dns::Message& msg) const
    {
        if (msg.questions.size() == 1)
        {
            // Hook every .sesh/.snode/.loki query
            for (auto tld : {CLIENT_TLD, RELAY_TLD, "loki"sv})
                if (msg.questions[0].has_tld(tld))
                    return true;

            // hook any PTR records for ranges we own
            if (msg.questions[0].qtype == srouter::dns::RRType::PTR)
            {
                if (auto ip = dns::decode_ptr(msg.questions[0].qname))
                {
                    if (auto* v4 = std::get_if<ipv4>(&*ip))
                        return _local_net.contains(*v4);
                    return _local_ipv6_net.contains(std::get<ipv6>(*ip));
                }
                return false;
            }
        }
        return false;
    }

    std::string TunEndpoint::get_if_name() const { return _if_name; }

    const ipv4& TunEndpoint::get_ipv4() const { return _local_net.ip; }
    const ipv6& TunEndpoint::get_ipv6() const { return _local_ipv6_net.ip; }

    const ipv4_net& TunEndpoint::get_ipv4_network() const { return _local_net; }
    const ipv6_net& TunEndpoint::get_ipv6_network() const { return _local_ipv6_net; }

    bool TunEndpoint::is_service_node() const { return _router.is_service_node; }

    bool TunEndpoint::is_exit_node() const { return _router.is_exit_node(); }

    bool TunEndpoint::stop()
    {
        // stop vpn tunnel
        if (_net_if)
            _net_if->Stop();
        if (_raw_DNS)
            _raw_DNS->Stop();

#if 0
        // save address map if applicable
        if (_persisting_addr_file and not platform::is_android)
        {
            const auto& file = *_persisting_addr_file;
            log::debug(logcat, "{} saving address map to {}", name(), file);
            // if (auto maybe = util::OpenFileStream<std::filesystem::ofstream>(file, std::ios_base::binary))
            // {
            //   std::map<std::string, std::string> addrmap;
            //   for (const auto& [ip, addr] : m_IPToAddr)
            //   {
            //     if (not m_SNodes.at(addr))
            //     {
            //       const service::Address a{addr.as_array()};
            //       if (HasInboundConvo(a))
            //         addrmap[ip.to_string()] = a.to_string();
            //     }
            //   }
            //   const auto data = oxenc::bt_serialize(addrmap);
            //   maybe->write(data.data(), data.size());
            // }
        }
#endif

        if (_dns)
            _dns->stop();

        return true;
    }

    template <typename RangeIterator>
    static std::optional<typename RangeIterator::ip_t> get_next_local_ipvX(
        RangeIterator& rit,
        const typename RangeIterator::ip_net_t& local_net,
        address_map<typename RangeIterator::ip_t>& local_mapping)
    {
        // if our IP range is exhausted, we loop back around to see if any have been unmapped from terminated
        // sessions; we only want to reset the iterator and loop back through once though
        bool has_reset = false;

        do
        {
            // this will be std::nullopt if IP range is exhausted OR the IP incrementing overflowed (basically
            // equal)
            if (auto maybe_next_ip = rit.next_ip())
            {
                if (not local_mapping.contains(*maybe_next_ip))
                    return maybe_next_ip;
                // local IP is already assigned; try again
                continue;
            }

            if (has_reset)
                break;

            log::debug(logcat, "Resetting IP range iterator for range: {}...", local_net);
            rit.reset();
            has_reset = true;
        } while (true);

        return std::nullopt;
    }

    std::optional<ipv4> TunEndpoint::get_next_local_ipv4()
    {
        return get_next_local_ipvX(_local_range_iterator, _local_net, _local_ipv4_mapping);
    }

    std::optional<ipv6> TunEndpoint::get_next_local_ipv6(const NetworkAddress& a)
    {
        // If we have at least a /64 (which we usually do) then first try using the prefix of `a` as
        // a network address itself; if this is available, we use it, so that typically the same
        // pubkey gets the same local address.  If that fails, however, because of a prefix
        // collision then we fall back to sequential allocation from the beginning of the range.
        uint8_t addr_bits = 128 - _local_ipv6_net.mask;

        const auto& rid = a.pubkey;
        size_t addr_bytes = addr_bits / 8;
        auto to_try = std::make_optional<ipv6>(_local_ipv6_net.ip);
        if (addr_bytes > 8)
        {
            uint64_t hi_bits = 0;
            std::memcpy(reinterpret_cast<char*>(&hi_bits) + 8 - (addr_bytes - 8), rid.data(), addr_bytes - 8);
            oxenc::big_to_host_inplace(hi_bits);
            to_try->hi |= hi_bits;
        }
        if (addr_bytes >= 8)
            to_try->lo = oxenc::load_big_to_host<uint64_t>(rid.data() + addr_bytes - 8);
        else
        {
            uint64_t lo_bits = 0;
            std::memcpy(reinterpret_cast<char*>(&lo_bits) + 8 - addr_bytes, rid.data(), addr_bytes);
            oxenc::big_to_host_inplace(lo_bits);
            to_try->lo |= lo_bits;
        }

        assert(_local_ipv6_net.contains(*to_try));
        if (!_local_ipv6_mapping.contains(*to_try) && *to_try != _local_ipv6_net.ip)
        {
            log::debug(logcat, "Assigning pubkey-based local IPv6 {} for remote {}", *to_try, a);
            return to_try;
        }
        log::debug(
            logcat,
            "Pubkey-based local IPv6 {} is already mapped; falling back to sequential IPv6 allocation",
            *to_try,
            a);

        return get_next_local_ipvX(_local_ipv6_range_iterator, _local_ipv6_net, _local_ipv6_mapping);
    }

    ipv6 TunEndpoint::map6(const NetworkAddress& remote)
    {
        ipv6 ret;
        if (auto maybe_ipv6 = _local_ipv6_mapping[remote])
        {
            ret = std::move(*maybe_ipv6);
            log::debug(logcat, "Local IP for session to remote ({}) already assigned ({})", remote, ret);
        }
        else if (auto maybe_next = get_next_local_ipv6(remote))
        {
            ret = std::move(*maybe_next);
            log::debug(logcat, "Local IP for session to remote ({}) assigned: {}", remote, ret);
            _local_ipv6_mapping.insert(ret, remote);
        }
        else
        {
            // This should not happen unless you have forced a stupidly small IPv6 range
            log::critical(logcat, "TUN device could not find a local private IPv6 for remote: {}", remote);
            throw std::runtime_error{
                "TUN device could not allocate an IPv6; perhaps the IPv6 netmask is much too restrictive?"};
        }

        return ret;
    }

    std::optional<ipv4> TunEndpoint::map4(const NetworkAddress& remote)
    {
        std::optional<ipv4> ret;

        // first: check if we already have a mapping for this remote
        ret = _local_ipv4_mapping[remote];
        if (ret)
            log::debug(logcat, "Local IP for session to remote ({}) already assigned ({})", remote, *ret);
        else
        {
            ret = get_next_local_ipv4();
            if (ret)
            {
                _local_ipv4_mapping.insert(*ret, remote);
                log::debug(logcat, "Local IP for session to remote ({}) assigned: {}", remote, *ret);
            }
            else
                log::error(
                    logcat,
                    "TUN device could not find a local private IPv4 for remote: {}; perhaps you need a "
                    "larger IPv4 network (i.e. smaller netmask)?",
                    remote);
        }

        return ret;
    }

    void TunEndpoint::expire(const NetworkAddress& remote)
    {
        // If already in the expired list, extract it before we re-add to the end
        if (auto it = _exp_it.find(remote); it != _exp_it.end())
        {
            _expired.erase(it->second);
            _exp_it.erase(it);
        }
        _exp_it[remote] = _expired.emplace(_expired.end(), remote);

        prune_expired();
    }

    void TunEndpoint::prune_expired()
    {
        size_t keep = _router.config().network.expired_address_cache;
        while (_expired.size() > keep)
        {
            auto& remote = _expired.front();
            _local_ipv4_mapping.erase(remote);
            _local_ipv6_mapping.erase(remote);
            _exp_it.erase(_expired.front());
            _expired.pop_front();
        }
    }

    // handles an outbound packet going OUT from user -> network
    void TunEndpoint::handle_outbound_packet(IPPacket pkt)
    {
        const bool is_v4 = pkt.is_ipv4();

        if (!is_v4 && !pkt.is_ipv6())
        {
            log::debug(logcat, "Dropping non-IP packet");
            log::trace(logcat, "Packet: {}", buffer_printer{pkt.span()});
            return;
        }

        log::trace(logcat, "outbound packet: {}: {}", pkt.info_line(), buffer_printer{pkt.span()});

        ipv4 src4, dest4;
        ipv6 src6, dest6;

        if (is_v4)
        {
            src4 = *pkt.source_ipv4();
            dest4 = *pkt.dest_ipv4();
            log::trace(logcat, "src:{}, dest:{}", src4, dest4);
        }
        else
        {
            src6 = *pkt.source_ipv6();
            dest6 = *pkt.dest_ipv6();
            log::trace(logcat, "src:{}, dest:{}", src6, dest6);
        }

        if constexpr (srouter::platform::is_apple)
        {
            if (is_v4)
            {
                if (dest4 == _local_net.ip)
                {
                    rewrite_and_send_packet(std::move(pkt), std::move(src4), std::move(dest4));
                    return;
                }
            }
            else if (dest6 == _local_ipv6_net.ip)
            {
                rewrite_and_send_packet(std::move(pkt), std::move(src6), std::move(dest6));
                return;
            }
        }

        // we pass `dest` because that is our local private IP on the outgoing IPPacket
        if (auto remote = is_v4 ? _local_ipv4_mapping[dest4] : _local_ipv6_mapping[dest6])
        {
            pkt.clear_addresses();

            if (auto session = _router.session_endpoint().get_session(*remote))
            {
                log::trace(
                    logcat,
                    "Dispatching outbound {}B packet for session (remote: {}): {}",
                    pkt.size(),
                    *remote,
                    pkt.info_line());
                session->send_session_data_message(pkt.span(), pkt.protocol());
            }
            else
            {
                log::debug(logcat, "No session for remote: {} for outbound packet, attempting to create one!", *remote);

                std::shared_ptr<session::Session> s;
                try
                {
                    s = _router.session_endpoint().initiate_remote_session(*remote, nullptr);
                }
                catch (const std::exception& e)
                {
                    log::debug(logcat, "Failed to auto-initiate session to remote {}: {}", *remote, e.what());
                }

                if (s)
                    s->send_session_data_message(pkt.span(), pkt.protocol());
            }
        }
        else
        {
            log::trace(logcat, "Could not find remote for route {}", pkt.info_line());

            // make ICMP unreachable
            if (auto icmp = pkt.make_icmp_unreachable())
                send_packet_to_net_if(std::move(*icmp));
        }
    }

    std::optional<ipv4> TunEndpoint::obtain_src_for_ipv4_remote(const NetworkAddress& remote)
    {
        if (auto maybe_src = _local_ipv4_mapping[remote])
            return maybe_src;

        log::warning(logcat, "Unable to find mapped IPv4 for inbound packet from remote {}", remote);
        return std::nullopt;
    }
    std::optional<ipv6> TunEndpoint::obtain_src_for_ipv6_remote(const NetworkAddress& remote)
    {
        if (auto maybe_src = _local_ipv6_mapping[remote])
            return maybe_src;

        log::warning(logcat, "Unable to find mapped IPv6 for inbound packet from remote {}", remote);
        return std::nullopt;
    }

    void TunEndpoint::send_packet_to_net_if(IPPacket pkt)
    {
        _router.loop.call([this, pkt = std::move(pkt)]() mutable { _net_if->write_packet(std::move(pkt)); });
    }

    void TunEndpoint::rewrite_and_send_packet(IPPacket&& pkt, const ipv4& src, const ipv4& dest)
    {
        pkt.update_ipv4_address(src, dest);
        send_packet_to_net_if(std::move(pkt));
    }
    void TunEndpoint::rewrite_and_send_packet(IPPacket&& pkt, const ipv6& src, const ipv6& dest)
    {
        pkt.update_ipv6_address(src, dest);
        send_packet_to_net_if(std::move(pkt));
    }

    // FIXME: we need separate flags for to-exit and from-exit
    void TunEndpoint::handle_inbound_packet(IPPacket pkt, uint8_t type, NetworkAddress remote)
    {
        (void)type;              // TODO FIXME use this
        bool to_exit = false;    // TODO FIXME
        bool from_exit = false;  // TODO FIXME

        if (to_exit)  // traffic exiting through this node
        {
            log::trace(logcat, "inbound exit pkt for exit node: {}", pkt.info_line());
            if (not is_allowing_traffic(pkt))
            {
                log::warning(logcat, "Dropping inbound exit packet: denied by local traffic policy");
                return;
            }

            if (pkt.is_ipv4())
            {
                if (auto src = obtain_src_for_ipv4_remote(remote))
                    return rewrite_and_send_packet(std::move(pkt), *src, *pkt.dest_ipv4());
            }
            else
            {
                if (auto src = obtain_src_for_ipv6_remote(remote))
                    return rewrite_and_send_packet(std::move(pkt), *src, *pkt.dest_ipv6());
            }
            return;
        }

        if (from_exit)  // return traffic coming back from an exit
        {
            log::trace(logcat, "inbound return exit pkt: {}", pkt.info_line());
            if (pkt.is_ipv4())
                rewrite_and_send_packet(std::move(pkt), *pkt.source_ipv4(), _local_net.ip);
            else
                rewrite_and_send_packet(std::move(pkt), *pkt.source_ipv6(), _local_ipv6_net.ip);
            return;
        }

        log::trace(logcat, "inbound pkt to host: {}", pkt.info_line());
        if (pkt.is_ipv4())
        {
            if (auto src = obtain_src_for_ipv4_remote(remote))
                return rewrite_and_send_packet(std::move(pkt), *src, _local_net.ip);
        }
        else
        {
            if (auto src = obtain_src_for_ipv6_remote(remote))
                return rewrite_and_send_packet(std::move(pkt), *src, _local_ipv6_net.ip);
        }
    }

    void TunEndpoint::start_poller()
    {
        _poller = std::make_unique<ev::FDPoller>(_router.loop, _net_if->PollFD(), [this] {
            for (auto pkt = _net_if->read_next_packet(); not pkt.empty(); pkt = _net_if->read_next_packet())
            {
                log::trace(logcat, "packet router receiving {}", pkt.info_line());
                _packet_router->handle_ip_packet(std::move(pkt));
            }
        });
        log::debug(logcat, "TUN successfully started FD poller!");
    }

    bool TunEndpoint::is_allowing_traffic(const IPPacket& pkt) const
    {
        return _exit_policy ? _exit_policy->allow_ip_traffic(pkt) : true;
    }

    std::pair<std::optional<ipv4>, std::optional<ipv6>> TunEndpoint::get_mapped_ip(const NetworkAddress& addr)
    {
        return {_local_ipv4_mapping[addr], _local_ipv6_mapping[addr]};
    }

    TunEndpoint::~TunEndpoint() { log::trace(logcat, "TunEndpoint::~TunEndpoint()"); }

}  // namespace srouter::handlers
