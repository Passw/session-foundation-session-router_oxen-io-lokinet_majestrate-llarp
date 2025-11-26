#pragma once

#include <nlohmann/json_fwd.hpp>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>

#include <string_view>
#include <tuple>

namespace srouter::dns
{
    inline constexpr size_t TARGET_MAX_SIZE{200};

    using SRVTuple = std::tuple<std::string, uint16_t, uint16_t, uint16_t, std::string>;

    /** SRVData

        bt-encoded keys:
            'p' : port
            's' : service protocol
            't' : target
            'u' : priority
            'w' : weight
    */
    struct SRVData
    {
        SRVData() = default;
        // SRVData constructor expecting a bt-encoded dictionary
        SRVData(oxenc::bt_dict_consumer&& btdc);
        SRVData(
            std::string svc, std::string proto, uint16_t priority, uint16_t weight, uint16_t port, std::string target);
        SRVData(std::string_view svc_proto, uint16_t priority, uint16_t weight, uint16_t port, std::string target);

        /* bind-like formatted string for SRV records in config file
         *
         * format:
         *   srv=_service._proto priority weight port target
         *
         * exactly one space character between parts.
         *
         * target can be empty, in which case the space after port should
         * be omitted.  if this is the case, the target is
         * interpreted as the .sesh of the current context.
         *
         * if target is not empty, it must be either
         *  - simply a full stop (dot/period) OR
         *  - a name within the .loki or .sesh subdomains. a target
         *    specified in this manner must not end with a full stop.
         */
        static std::optional<SRVData> from_srv_string(std::string buf);

        std::string service;
        std::string proto;
        uint16_t priority;
        uint16_t weight;
        uint16_t port;

        // target string for the SRV record to point to
        // options:
        //   empty                     - refer to query name
        //   dot                       - authoritative "no such service available"
        //   any other .loki or .sesh  - target is that .loki or .sesh
        std::string target;

        // do some basic validation on the target string
        // note: this is not a conclusive, regex solution,
        // but rather some sanity/safety checks
        bool is_valid() const;

        bool operator==(const SRVData& other) const = default;

        void bt_encode(oxenc::bt_dict_producer&& btdp) const;

        // TESTNET: TODO: remove this after refactoring IntroSet -> ClientContact
        std::string bt_encode() const;

        bool bt_decode(std::string buf);

      private:
        bool bt_decode(oxenc::bt_dict_consumer&& btdc);
        bool from_string(std::string_view srvString);
    };

}  // namespace srouter::dns
