#pragma once

#include "encode.hpp"
#include "srv_data.hpp"

#include <nlohmann/json_fwd.hpp>

#include <chrono>
#include <span>
#include <vector>

namespace srouter::dns
{
    enum class RRClass : uint16_t
    {
        IN = 1,
    };
    enum class RRType : uint16_t
    {
        A = 1,
        CNAME = 5,
        PTR = 12,
        TXT = 16,
        AAAA = 28,
        SRV = 33,
    };

    struct ResourceRecord
    {
        ResourceRecord(std::string rr_name, std::chrono::seconds ttl) : rr_name{std::move(rr_name)}, ttl{ttl} {}

        // Writes this RR to the beginning of buf, eliminating the written section from buf.  Throws if buf is exceeded.
        //
        // This takes care of the basic stuff (name, type, class, ttl), then calls the virtual
        // encode_data() to write the value.
        void encode(std::span<std::byte>& buf, prev_names_t& prev_names, uint16_t& buf_offset) const;

        virtual void encode_data(std::span<std::byte>& buf, prev_names_t& prev_names, uint16_t& buf_offset) const = 0;

        nlohmann::json ToJSON() const;

        std::string to_string() const;

        std::string rr_name;
        RRClass rr_class = RRClass::IN;
        std::chrono::seconds ttl;

        virtual RRType rr_type() const = 0;

        static constexpr bool to_string_formattable = true;
    };

    // Subclass of ResourceRecord that just has a binary check of data.  Should not be used for data
    // types containing compressible names in the value.  The subclass must take care of encoding
    // the rData member value as required; this base class encode_data simply barfs it into the
    // buffer as-is.
    struct RR_bytes : ResourceRecord
    {
        std::vector<std::byte> rData;

        using ResourceRecord::ResourceRecord;

        void encode_data(std::span<std::byte>& buf, prev_names_t& prev_names, uint16_t& buf_offset) const override;
    };

    struct RR_A : RR_bytes
    {
        RR_A(std::string rr_name, std::chrono::seconds ttl, const ipv4& addr);
        RRType rr_type() const override { return RRType::A; }
    };
    struct RR_AAAA : RR_bytes
    {
        RR_AAAA(std::string rr_name, std::chrono::seconds ttl, const ipv6& addr);
        RRType rr_type() const override { return RRType::AAAA; }
    };
    struct RR_TXT : RR_bytes
    {
        RR_TXT(std::string rr_name, std::chrono::seconds ttl, std::string_view value);
        RRType rr_type() const override { return RRType::TXT; }
    };

    // Base class for RR types that have a single target name as the value, such as CNAME and PTR
    struct RR_target : ResourceRecord
    {
        std::string name;

        RR_target(std::string rr_name, std::chrono::seconds ttl, std::string name)
            : ResourceRecord{std::move(rr_name), ttl}, name{std::move(name)}
        {}

        void encode_data(std::span<std::byte>& buf, prev_names_t& prev_names, uint16_t& buf_offset) const override;
    };

    struct RR_PTR : RR_target
    {
        using RR_target::RR_target;
        RRType rr_type() const override { return RRType::A; }
    };
    struct RR_CNAME : RR_target
    {
        using RR_target::RR_target;
        RRType rr_type() const override { return RRType::CNAME; }
    };
    struct RR_SRV : ResourceRecord
    {
        uint16_t priority;
        uint16_t weight;
        uint16_t port;
        std::string target;

        RR_SRV(std::string rr_name, std::chrono::seconds ttl, const SRVData& srv)
            : ResourceRecord{std::move(rr_name), ttl},
              priority{srv.priority},
              weight{srv.weight},
              port{srv.port},
              target{srv.target}
        {}

        RRType rr_type() const override { return RRType::SRV; }
        void encode_data(std::span<std::byte>& buf, prev_names_t& prev_names, uint16_t& buf_offset) const override;
    };
}  // namespace srouter::dns
