#include "name.hpp"

#include "address/address.hpp"
#include "util/str.hpp"

#include <oxenc/endian.h>
#include <oxenc/hex.h>

namespace srouter::dns
{
    std::optional<std::string> DecodeName(buffer_t* buf, bool trimTrailingDot)
    {
        if (buf->size_left() < 1)
            return std::nullopt;
        auto result = std::make_optional<std::string>();
        auto& name = *result;
        size_t l;
        do
        {
            l = *buf->cur;
            buf->cur++;
            if (l)
            {
                if (buf->size_left() < l)
                    return std::nullopt;

                name.append((const char*)buf->cur, l);
                name += '.';
            }
            buf->cur = buf->cur + l;
        } while (l);
        /// trim off last dot
        if (trimTrailingDot)
            name.pop_back();
        return result;
    }

    bool EncodeNameTo(buffer_t* buf, std::string_view name)
    {
        if (name.size() && name.back() == '.')
            name.remove_suffix(1);

        for (auto part : srouter::split(name, "."))
        {
            size_t l = part.length();
            if (l > 63)
                return false;
            *(buf->cur) = l;
            buf->cur++;
            if (buf->size_left() < l)
                return false;
            if (l)
            {
                std::memcpy(buf->cur, part.data(), l);
                buf->cur += l;
            }
            else
                break;
        }
        *buf->cur = 0;
        buf->cur++;
        return true;
    }

    std::optional<std::variant<ipv4, ipv6>> DecodePTR(std::string_view name)
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

    bool NameIsReserved(std::string_view name)
    {
        if (name.ends_with('.'))
            name.remove_suffix(1);
        if (name.ends_with(".loki"sv) || name.ends_with(CLIENT_DOT_TLD))
        {
            name.remove_suffix(5);
            for (const auto& sld : {CLIENT_DOT_TLD, RELAY_DOT_TLD, ".loki"sv})
                if (name.ends_with(sld) || name == sld.substr(1))
                    return true;
        }

        return false;
    }
}  // namespace srouter::dns
