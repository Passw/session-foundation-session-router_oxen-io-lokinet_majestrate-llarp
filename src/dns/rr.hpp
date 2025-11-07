#pragma once

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
        NS = 2,
        CNAME = 5,
        PTR = 12,
        MX = 15,
        TXT = 16,
        AAAA = 28,
        SRV = 33,
    };

    struct ResourceRecord
    {
        ResourceRecord() = default;
        explicit ResourceRecord(std::string name, RRType type, std::vector<std::byte> rdata);

        // Writes this RR to the beginning of buf.  Returns the number of bytes written, or 0 if the
        // buffer is too small to hold it.
        size_t encode(std::span<std::byte> buf) const;

        nlohmann::json ToJSON() const;

        std::string to_string() const;

        std::string rr_name;
        RRType rr_type;
        RRClass rr_class;
        std::chrono::seconds ttl;
        std::vector<std::byte> rData;

        static constexpr bool to_string_formattable = true;
    };
}  // namespace srouter::dns
