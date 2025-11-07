#include "rr.hpp"

#include "dns.hpp"
#include "encode.hpp"

#include <fmt/chrono.h>
#include <nlohmann/json.hpp>

namespace srouter::dns
{
    ResourceRecord::ResourceRecord(std::string name, RRType type, std::vector<std::byte> data)
        : rr_name{std::move(name)}, rr_type{type}, rr_class{RRClass::IN}, ttl{1s}, rData{std::move(data)}
    {}

    size_t ResourceRecord::encode(std::span<std::byte> buf) const
    {
        auto orig = buf.size();
        if (write_name_into(buf, rr_name)
            && write_ints_into(
                buf,
                static_cast<uint16_t>(rr_type),
                static_cast<uint16_t>(rr_class),
                static_cast<uint32_t>(ttl.count()))
            && write_rdata_into(buf, rData))
            return orig - buf.size();
        return 0;
    }

    nlohmann::json ResourceRecord::ToJSON() const
    {
        return nlohmann::json{
            {"name", rr_name},
            {"type", static_cast<uint16_t>(rr_type)},
            {"class", static_cast<uint16_t>(rr_class)},
            {"ttl", ttl.count()},
            {"rdata", std::string{reinterpret_cast<const char*>(rData.data()), rData.size()}}};
    }

    std::string ResourceRecord::to_string() const
    {
        return "RR:[ name:{} | type:{} | class:{} | ttl:{} | rdata-size:{} ]"_format(
            rr_name, static_cast<uint16_t>(rr_type), static_cast<uint16_t>(rr_class), ttl, rData.size());
    }

}  // namespace srouter::dns
