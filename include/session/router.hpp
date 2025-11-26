#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <thread>
#include <type_traits>

namespace srouter
{
    struct Context;
    struct Config;
}  // namespace srouter

namespace oxen::quic
{
    class Loop;
}

namespace session::router
{
    enum class Network
    {
        MAINNET,
        TESTNET
    };

    /// Object returned when establishing a session for a TCP or UDP tunnel.  The tunnel port will
    /// be kept open until close_udp()/close_tcp() is called with the same remote and port.
    struct tunnel_info
    {
        /// The requested remote address.  If an ONS entry was requested, this will be the resolved
        /// "fulladdress.loki" rather than the ONS entry value.
        std::string remote;

        /// The requested remote port.  Packets sent to the `local_port` are delivered to this
        /// remote port, and returning packets from that remote back to the incoming source are
        /// routed back to the client and delivered to the source port that sent the original
        /// packet.  Multiple connections to the same address are possible: each different source
        /// port establishes a separate connection (actual TCP connections for TCP, a remembered
        /// mapping for UDP).
        uint16_t remote_port;

        /// The bound local port.  After establishing a Session Router session, clients connect
        /// (TCP) or send (UDP) to this port (on IPv6 localhost address ::1) to reach the
        /// destination through session_router.
        uint16_t local_port;

        /// A suggested maximum MTU for the connection.  If the application supports a configurable
        /// MTU, this value is the recommended value that avoids some additional overhead from
        /// packet splitting, which can slightly reduce latency and jitter.  If the application
        /// doesn't support MTU configuration then this value can simply be ignored and Session
        /// Router will split any "too large" packets into two.
        uint16_t suggested_mtu;
    };

    using snode_path = std::vector<std::pair<std::string, std::string>>;
    using session_path = std::pair<snode_path, std::string>;

    class SessionRouter
    {
        std::unique_ptr<srouter::Context> context;

        struct path_ctor
        {};
        SessionRouter(path_ctor, const std::filesystem::path& p, std::shared_ptr<oxen::quic::Loop> loop);

      public:
        // Starts an embedded Session Router that loads the given string contents as a config file.
        explicit SessionRouter(std::string config, std::shared_ptr<oxen::quic::Loop> existing_loop = nullptr);

        // Starts an embedded Session Router instance with extra configuration specified in the given
        // config file.  (Templatized to avoid ambiguous implicit conversion from std::string
        // conflicting with the constructor above.)
        template <std::same_as<std::filesystem::path> FSPath>
        explicit SessionRouter(const FSPath& config, std::shared_ptr<oxen::quic::Loop> existing_loop = nullptr)
            : SessionRouter{path_ctor{}, config, std::move(existing_loop)}
        {}

        // Starts an embedded Session Router with default config that runs on the given network with
        // default settings.
        explicit SessionRouter(Network network, std::shared_ptr<oxen::quic::Loop> existing_loop = nullptr);

        // Destructor stops the Session Router instance.  The destructor blocks until shutdown is complete.
        ~SessionRouter();

        // Schedules the given callback to be fired when Session Router edge connections are mostly
        // established (and thus Session Router is ready to start building paths).  If Session
        // Router is already established, this will schedule an immediate invocation of the
        // callback.
        //
        // If the `with_path` argument is true (or omitted) then the callback instead fires with
        // there are edge connections *and* at least one inbound/utility path, which is needed to be
        // able to query the network for things like ONS records and client contacts.  `false`, on
        // the other hand, will fire sooner without requiring a path be completed: it is suitable
        // for signalling when Session Router is sufficient connected to start building sessions to
        // relays.
        //
        // If persist is true then the callback will be stored and called *each* time Session Router enters
        // the connected state (i.e. it will be called again if Session Router loses all connectivity and
        // then regains connections and/or paths).
        void on_connected(std::function<void()> callback, bool with_path = true, bool persist = false);

        // Schedules the given callback to be fired when Session Router becomes fully disconnected,
        // i.e.  loses all established edge connections or its last inbound path.  When `with_path`
        // is given and false, this tracks edge disconnection, which means the instance has lost all
        // connectivity; when omitted or true, the callback is also fired if the last inbound path
        // is lost, signalling that network querying and client sessions cannot currently work, but
        // sessions to relays may still be functional.
        //
        // If `persist` is true then the callback will be fired *each* time Session Router
        // transitions from connected to disconnected state.  If Session Router
        // is not currently connected then the callback will be scheduled immediately.
        void on_disconnected(std::function<void()> callback, bool with_path = true, bool persist = false);

        // Establishes a session to the given remote (pubkey.sesh or pubkey.snode), with an IPv6
        // localhost port mapped to a port on the remote.  A limited number of packets (e.g. to
        // establish a connection) can be sent to the mapped port immediately even before the
        // session establishes: a few packets will be queued and delivered once (and if) the session
        // establishes.
        //
        // (This method does not accept SNS names: you need to call resolve_sns() first for that).
        //
        // The returned object contains the port information.  The tunnel will remain active until
        // drop_udp() is called with the same remote address and port (or the SessionRouter instance
        // is destroyed).  The caller should track this and drop UDP ports when no longer needed.
        //
        // Calling with an already-established remote/port simply returns that existing mapping, it
        // does *not* create a new one.
        //
        // This method will throw if the given address is unparseable.
        //
        // If an `on_established` callback is provided then it will be called once the full session
        // is established, and passed the same tunnel_info data that was returned by the initial
        // call.  Note that `on_established` can be called immediately (i.e. before
        // `establish_udp()` returns), if a session to the remote is already established.
        //
        // `on_timeout` is invoked instead of `on_established` if the session fails to establish.
        // Note that:
        // - `on_timeout` is *not* called if the call throws (such as if given an unparseable
        //   address).
        // - an `on_timeout` call does *not* mean the tunnel has been cancelled: it will remain
        //   active and future attempts to connect to the tunnel port will attempt to (re-)establish
        //   the session.  If you want to cancel it on session initiation failure, you must call
        //   `close_udp()` from within the on_timeout callback.
        //
        // Take care not to use very slow or blocking code inside the callbacks: they are called
        // from Session Router's logic thread (and so any blocking will stall Session Router).
        tunnel_info establish_udp(
            std::string_view remote,
            uint16_t port,
            std::function<void(tunnel_info)> on_established = nullptr,
            std::function<void()> on_timeout = nullptr);

        // Closes a tunnel socket to the given remote/port combination, releasing any internal
        // mappings set up from previous connections through the tunnel.
        void close_udp(std::string_view remote, uint16_t port);

        // Takes an ONS/SNS address such as "blocks.loki" and attempts to resolve it to a Session
        // Router client (aka hidden service) address such as
        // "kcpyawm9se7trdbzncimdi5t7st4p5mh9i1mg7gkpuubi4k4ku1y.sesh".
        //
        // This method will also accept a full network address (PUBKEY.sesh or PUBKEY.snode), in
        // which case it simply instantly calls the callback with the same address.  (This
        // capability is designed to allow this method to be used with an address that could be
        // either ONS/SNS or direct pubkey).
        //
        // When the name is resolved, the callback will be invoked with the network address.  If the
        // name does not exist or a timeout occurs it will be invoked with nullopt and a second
        // argument that is true if we timed out (i.e. don't know), false if we got a definitive
        // answer from the network that the name does not exist.  (The bool should not be used when
        // `addr` has a value).
        //
        // It is possible for the callback to be called instantly (i.e. before resolve_sns returns)
        // if the result is already cached, or when given a direct pubkey address rather than a
        // resolvable ONS/SNS name.
        //
        // This method will throw an invalid_argument exception if the given address is neither a
        // valid pubkey address nor potentially valid ONS/SNS address.
        void resolve(std::string address, std::function<void(std::optional<std::string> addr, bool timeout)> callback);

        // If we have a session with the given remote, returns the path we are currently using for
        // that session.  In the case of a client<->client session, this will be the relay which we
        // are using as a pivot.
        //
        // If there is a session but no current path, an empty vector is
        // returned.
        // If there is not a session to the remote, std::nullopt is returned.
        std::optional<snode_path> get_path_for_session(std::string_view remote);

        // Returns the path we're currently using for each session along with the remote endpoint
        // of that session.  In the case of snode (relay) sessions, the remote endpoint will be
        // the same as the path terminus.  In the case of client<->client sessions, the remote
        // endpoint is the client which we're connected to via that path as a relay.
        std::vector<session_path> get_all_session_paths();
    };

    template SessionRouter::SessionRouter(const std::filesystem::path&, std::shared_ptr<oxen::quic::Loop>);

}  // namespace session::router
