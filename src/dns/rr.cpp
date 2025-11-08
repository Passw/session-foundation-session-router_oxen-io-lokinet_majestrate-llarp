#include "rr.hpp"

#include "dns.hpp"
#include "encode.hpp"

#include <fmt/chrono.h>
#include <nlohmann/json.hpp>

#include <stdexcept>

namespace srouter::dns
{
    void ResourceRecord::encode(std::span<std::byte>& buf, prev_names_t& prev_names, uint16_t& buf_offset) const
    {
        encode_name(buf, rr_name, prev_names, buf_offset);
        buf_offset += write_ints_into(
            buf, static_cast<uint16_t>(rr_type()), static_cast<uint16_t>(rr_class), static_cast<uint32_t>(ttl.count()));
        // The RR value is in a chunk with a 2-byte length in front of it.  We don't actually know
        // the length yet (especially for things like CNAME, where there might be name compression),
        // so we're going to stick a 0 in and then come back and fill it in after we write the
        // value.
        if (buf.size() < 2)
            throw std::out_of_range{"Buffer too small"};
        auto size_buf = buf.subspan(0, 2);
        buf_offset += 2;
        buf = buf.subspan(2);
        encode_data(buf, prev_names, buf_offset);
        uint16_t size = buf.data() - size_buf.data() - 2;
        oxenc::write_host_as_big(size, size_buf.data());
    }

    nlohmann::json ResourceRecord::ToJSON() const
    {
        return nlohmann::json{
            {"name", rr_name},
            {"type", static_cast<uint16_t>(rr_type())},
            {"class", static_cast<uint16_t>(rr_class)},
            {"ttl", ttl.count()},
            /* FIXME: need to virtualize a display for the data, if we care about json representation:
            {"rdata", std::string{reinterpret_cast<const char*>(rData.data()), rData.size()}}*/};
    }

    std::string ResourceRecord::to_string() const
    {
        return "RR:[name:{}|type:{}|class:{}|ttl:{}]"_format(
            rr_name, static_cast<uint16_t>(rr_type()), static_cast<uint16_t>(rr_class), ttl);
    }

    void RR_bytes::encode_data(std::span<std::byte>& buf, prev_names_t&, uint16_t& buf_offset) const
    {
        if (rData.size() > buf.size())
            throw std::out_of_range{"Buffer too small"};
        std::memcpy(buf.data(), rData.data(), rData.size());
        buf = buf.subspan(rData.size());
        buf_offset += rData.size();
    }

    RR_A::RR_A(std::string rr_name, std::chrono::seconds ttl, const ipv4& addr) : RR_bytes{std::move(rr_name), ttl}
    {
        rData.resize(4);
        oxenc::write_host_as_big(addr.addr, rData.data());
    }

    RR_AAAA::RR_AAAA(std::string rr_name, std::chrono::seconds ttl, const ipv6& addr)
        : RR_bytes{std::move(rr_name), ttl}
    {
        rData.resize(16);
        oxenc::write_host_as_big(addr.hi, rData.data());
        oxenc::write_host_as_big(addr.lo, rData.data() + 8);
    }

    RR_TXT::RR_TXT(std::string rr_name, std::chrono::seconds ttl, std::string_view value)
        : RR_bytes{std::move(rr_name), ttl}
    {
        auto* bytes = reinterpret_cast<const std::byte*>(value.data());
        rData.assign(bytes, bytes + value.size());
    }

    void RR_target::encode_data(std::span<std::byte>& buf, prev_names_t& prev_names, uint16_t& buf_offset) const
    {
        encode_name(buf, name, prev_names, buf_offset);
    }

    void RR_SRV::encode_data(std::span<std::byte>& buf, prev_names_t& prev_names, uint16_t& buf_offset) const
    {
        buf_offset += write_ints_into(buf, priority, weight, port);
        encode_name(buf, target, prev_names, buf_offset);
    }

}  // namespace srouter::dns
