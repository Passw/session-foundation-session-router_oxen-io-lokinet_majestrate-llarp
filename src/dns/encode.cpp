#include "encode.hpp"

#include "address/address.hpp"
#include "util/logging.hpp"
#include "util/logging/buffer.hpp"
#include "util/str.hpp"

#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <limits>

namespace srouter::dns
{
    static auto logcat = log::Cat("dns");

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

    std::optional<std::span<const std::byte>> extract_name_data(std::span<const std::byte>& buf)
    {
        log::trace(logcat, "Extracting name data from: {}", buffer_printer{buf});
        auto* p = buf.data();
        auto* end = p + buf.size();
        while (true)
        {
            if (p == end)
                return std::nullopt;
            auto len = static_cast<size_t>(*p++);
            if (len > 63)
            {
                // This is a compressed name pointer, so we need this byte and the next one, and
                // then that's it, we're done.
                if (p == end)
                    return std::nullopt;
                p++;
                break;
            }

            if (len == 0)
                break;  // Terminating null

            // Otherwise we have a length prefix:
            if (p + len >= end)
                return std::nullopt;
            p += len;
        }

        auto result = std::make_optional<std::span<const std::byte>>(buf.subspan(0, p - buf.data()));
        buf = buf.subspan(p - buf.data());
        return result;
    }

    void encode_name(std::span<std::byte>& buf, std::string_view name, prev_names_t* prev_names, uint16_t* buf_offset)
    {
        if (name.size() && name.back() == '.')
            name.remove_suffix(1);

        assert((prev_names && buf_offset) || (!prev_names && !buf_offset));

        // Look for a previously used suffix of this name.  For instance, if we have a response
        // consisting of:
        //
        // localhost.sesh IN CNAME mylongpubkey.sesh
        // foo.mylongpubkey.sesh IN AAAA 1:2:3::4
        //
        // then when we repeat the question itself (IN AAAA localhost.sesh) we echo that question
        // back into the response as the 16 bytes:
        //     \x09localhost\x04sesh\x00
        // Suppose that this was written at location Z in the DNS message, this creates two
        // pointable addresses:
        // - "localhost.sesh" -> Z
        // - "sesh" -> Z+10
        //
        // Then we come to the answers, and for the first "localhost.sesh" value, we can simply
        // write that as a single pointer [Z] (where the pointer is a 16-bit, big-endian value with
        // the highest two bits set and the remaining 14 bits set to "Z").
        //
        // Then we get to "mylongpubkey.sesh" and we can encode that as:
        //
        //     \x34mylongpubkey[pointer to Z+10]
        //
        // This also creates a new pointable address:
        // - "mylongpubkey.sesh" -> Y
        //
        // Then we come to foo.mylongpubkey.sesh and we can encode this as:
        //
        // - \x03foo[pointer to Y]
        //
        // i.e. we only need 6 bytes for this address instead of 1+3+1+52+1+4+1=63 bytes that we
        // would need for the uncompressed version.
        //
        // Although this compression is optional, given how frequently we reuse long session router
        // names (particularly for something like SRV records where a name can be repeated multiple
        // times), and the DNS response size limit of 512 bytes, we implement that here.

        for (size_t pos = name.empty() ? std::string::npos : 0; pos != std::string_view::npos;)
        {
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 11
            // Workaround for gcc bug (fixed in gcc 11) which doesn't allow us to pass a string_view
            // to unordered_map `find()` with a std::string key.
            std::string check{name.substr(pos)};
#else
            std::string_view check = name.substr(pos);
#endif
            if (prev_names)
                if (auto it = prev_names->find(check); it != prev_names->end())
                {
                    if (buf.size() < 2)
                        throw std::out_of_range{"Buffer too small"};
                    uint16_t ptr = uint16_t{0b11000000'00000000} | it->second;
                    oxenc::write_host_as_big(ptr, buf.data());
                    buf = buf.subspan(2);
                    *buf_offset += 2;
                    // A pointer is terminal (i.e. no nullptr to add), so we're done.
                    return;
                }

            auto next = name.find('.', pos + 1);
            auto part = next == std::string_view::npos ? check : name.substr(pos, next - pos);

            size_t l = part.size();
            if (l > 63 || l >= buf.size())
                throw std::out_of_range{"Buffer too small"};
            buf.front() = static_cast<std::byte>(l);  // Length prefix
            std::memcpy(buf.data() + 1, part.data(), part.size());
            if (prev_names)
            {
                prev_names->emplace(std::string{check}, static_cast<uint16_t>(*buf_offset));
                *buf_offset += 1 + part.size();
            }
            buf = buf.subspan(1 + part.size());

            pos = next == std::string_view::npos ? next : next + 1;
        }

        // If we get here we wrote all the pieces without pointing at anything, so we need to append
        // a null byte to terminate the name:
        if (buf.empty())
            throw std::out_of_range{"Buffer too small"};
        buf.front() = std::byte{0};
        buf = buf.subspan(1);
        if (buf_offset)
            ++*buf_offset;
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
