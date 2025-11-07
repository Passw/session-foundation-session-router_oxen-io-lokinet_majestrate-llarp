#include "encode.hpp"

#include "address/address.hpp"
#include "util/str.hpp"

#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <limits>

namespace srouter::dns
{
    std::optional<std::string> extract_name(std::span<const std::byte>& buf)
    {
        std::optional<std::string> name;
        if (buf.empty())
            return name;
        name.emplace();
        auto b = buf;  // Work on a copy in case we have to abort midway through
        while (true)
        {
            if (b.empty())
            {
                name.reset();
                return name;
            }

            auto len = static_cast<size_t>(b.front());
            b = b.subspan(1);
            if (!len)
                break;
            if (len >= b.size())
            {
                name.reset();
                return name;
            }
            name->append(reinterpret_cast<const char*>(b.data()), len);
            *name += '.';
            b = b.subspan(len);
        }

        if (name->empty())
            *name += '.';

        buf = b;
        return name;
    }

    size_t encode_name(std::span<std::byte> buf, std::string_view name)
    {
        auto orig = buf.size();
        if (name.size() && name.back() == '.')
            name.remove_suffix(1);

        for (auto part : srouter::split(name, "."))
        {
            size_t l = part.size();
            if (l > 63 || l >= buf.size())
                return false;
            buf.front() = static_cast<std::byte>(l);
            std::memcpy(buf.data() + 1, part.data(), part.size());
            buf = buf.subspan(1 + part.size());
        }
        if (buf.empty())
            return false;
        buf.front() = std::byte{0};
        buf = buf.subspan(1);
        return orig - buf.size();
    }

    bool write_name_into(std::span<std::byte>& buf, std::string_view name)
    {
        if (auto s = encode_name(buf, name))
        {
            buf = buf.subspan(s);
            return true;
        }
        return false;
    }

    std::optional<std::variant<ipv4, ipv6>> decode_ptr(std::string_view name)
    {
        bool isV6 = false;
        auto pos = name.find(".in-addr.arpa");

        if (pos == std::string::npos)
        {
            pos = name.find(".ip6.arpa");
            isV6 = true;
        }

        if (pos == std::string::npos)
            return std::nullopt;

        name = name.substr(0, pos + 1);
        const auto numdots = std::count(name.begin(), name.end(), '.');

        if (numdots == 4 && !isV6)
        {
            std::array<uint8_t, 4> q;

            for (int i = 3; i >= 0; i--)
            {
                pos = name.find('.');
                if (!srouter::parse_int(name.substr(0, pos), q[i]))
                    return std::nullopt;
                name.remove_prefix(pos + 1);
            }

            return ipv4(q[0], q[1], q[2], q[3]);
        }
        if (numdots == 32 && name.size() == 64 && isV6)
        {
            // We're going to convert from nybbles a.b.c.d.e.f.0.1.2.3.[...] into hex string
            // "badcfe1032...", then decode the hex string to bytes.
            std::array<char, 32> in;
            auto in_pos = in.data();

            for (size_t i = 0; i < 64; i += 4)
            {
                if (not(oxenc::is_hex_digit(name[i]) and name[i + 1] == '.' and oxenc::is_hex_digit(name[i + 2])
                        and name[i + 3] == '.'))
                    return std::nullopt;

                // Flip the nybbles because the smallest one is first
                *in_pos++ = name[i + 2];
                *in_pos++ = name[i];
            }

            assert(in_pos == in.data() + in.size());

            // our string right now is the little endian hex representation, so reading that
            // directly into the lo/hi values will suffice for little-endian, but need a flip for
            // big endian:
            ipv6 result;
            oxenc::from_hex(in.begin(), in.begin() + 16, reinterpret_cast<char*>(&result.lo));
            oxenc::from_hex(in.begin() + 16, in.end(), reinterpret_cast<char*>(&result.hi));
            oxenc::little_to_host_inplace(result.lo);
            oxenc::little_to_host_inplace(result.hi);
            return result;
        }
        return std::nullopt;
    }

    bool write_rdata_into(std::span<std::byte>& buf, std::span<const std::byte> rdata)
    {
        if (rdata.size() > std::numeric_limits<uint16_t>::max())
            return false;
        if (sizeof(uint16_t) + rdata.size() > buf.size())
            return false;
        oxenc::write_host_as_big<uint16_t>(rdata.size(), buf.data());
        std::memcpy(buf.data() + sizeof(uint16_t), rdata.data(), rdata.size());
        buf = buf.subspan(sizeof(uint16_t) + rdata.size());
        return true;
    }

    std::optional<std::vector<std::byte>> extract_rdata(std::span<const std::byte>& buf)
    {
        if (buf.size() < 2)
            return std::nullopt;
        auto len = oxenc::load_big_to_host<uint16_t>(buf.data());
        if (buf.size() < 2U + len)
            return std::nullopt;

        auto* p = buf.data() + 2;
        buf = buf.subspan(2 + len);
        return std::make_optional<std::vector<std::byte>>(p, p + len);
    }

}  // namespace srouter::dns
