#include "utils.hpp"

#include "util/logging.hpp"

namespace srouter
{
    static auto logcat = log::Cat("net-utils");

    namespace utils
    {
        static constexpr uint32_t add32_cs(uint32_t x) { return uint32_t{x & 0xFFff} + uint32_t{x >> 16}; }
        static constexpr uint32_t add32_cs(const ipv4 &x) { return add32_cs(oxenc::host_to_big(x.addr)); }

        static constexpr uint32_t sub32_cs(uint32_t x) { return add32_cs(~x); }
        static constexpr uint32_t sub32_cs(const ipv4 &x) { return sub32_cs(oxenc::host_to_big(x.addr)); }

        static constexpr uint32_t add32x4_cs(std::span<const uint32_t, 4> x)
        {
            return add32_cs(x[0]) + add32_cs(x[1]) + add32_cs(x[2]) + add32_cs(x[3]);
        }
        static constexpr uint32_t sub32x4_cs(std::span<const uint32_t, 4> x)
        {
            return sub32_cs(x[0]) + sub32_cs(x[1]) + sub32_cs(x[2]) + sub32_cs(x[3]);
        }

        uint16_t ip_checksum(const uint8_t *buf, size_t sz)
        {
            uint32_t sum = 0;

            while (sz > 1)
            {
                sum += *(uint16_t *)(buf);
                sz -= sizeof(uint16_t);
                buf += sizeof(uint16_t);
            }

            if (sz != 0)
            {
                uint16_t x = 0;
                *(uint8_t *)&x = *buf;
                sum += x;
            }

            sum = (sum & 0xFFff) + (sum >> 16);
            sum += sum >> 16;

            return uint16_t((~sum) & 0xFFff);
        }

        uint16_t update_ipv4_checksum(
            uint16_t old_sum, uint32_t old_src, uint32_t old_dest, const ipv4 &new_src, const ipv4 &new_dest)
        {
            uint32_t sum = old_sum + add32_cs(old_src) + add32_cs(old_dest) + sub32_cs(new_src) + sub32_cs(new_dest);

            sum = (sum & 0xFFff) + (sum >> 16);
            sum += sum >> 16;

            return uint16_t(sum & 0xFFff);
        }

        uint16_t update_ipv4_tcp_checksum(
            uint16_t old_sum, uint32_t old_src, uint32_t old_dest, const ipv4 &new_src, const ipv4 &new_dest)
        {
            auto new_sum = update_ipv4_checksum(old_sum, old_src, old_dest, new_src, new_dest);
            // With 1's complement, 0xffff is -0 but that can never actually appear in a checksum
            // with any non-zero bytes (which will always be present here), so this corrects it to
            // the proper 0x000 (+0) value that it should have:
            return new_sum == 0xFFff ? 0x0000 : new_sum;
        }

        uint16_t update_ipv4_udp_checksum(
            uint16_t old_sum, uint32_t old_src, uint32_t old_dest, const ipv4 &new_src, const ipv4 &new_dest)
        {
            if (old_sum == 0x0000)
                return old_sum;  // 0 is used to indicate "no checksum", don't change

            return update_ipv4_checksum(old_sum, old_src, old_dest, new_src, new_dest);
        }

        uint16_t update_ipv6_checksum(
            uint16_t old_sum,
            std::span<const uint32_t, 4> old_src,
            std::span<const uint32_t, 4> old_dest,
            std::span<const uint32_t, 4> new_src,
            std::span<const uint32_t, 4> new_dest)
        {
            // It seems a little counterintuitive that we aren't doing endian conversions here, but
            // that's actually okay because even if we have a "wrong" byte order interpretation, we
            // have the same wrong interpretation for old_sum, and because we're using 1's
            // complement, it all works out in the end regardless of endianness.
            uint32_t sum = uint32_t{old_sum} + add32x4_cs(old_src) + add32x4_cs(old_dest) + sub32x4_cs(new_src)
                + sub32x4_cs(new_dest);

            sum = (sum & 0xFFff) + (sum >> 16);
            sum += sum >> 16;

            return static_cast<uint16_t>(sum & 0xFFff);
        }

        // Modifies the payload's checksum at `checksumoff` to account for a change in source and
        // destination IPv6 addresses.  Unlike IPv4 which has a checksum over source and dest, IPv6
        // does not, and some protocols require it under IPv6 (such as UDP where it can be optional
        // under IPv4, and ICMP(v4) which doesn't checksum addresses at all, unlike ICMPv6).
        void update_ipv6_proto_checksum(
            std::span<std::byte> payload,
            size_t fragoff,
            size_t chksumoff,
            std::span<const uint32_t, 4> old_src,
            std::span<const uint32_t, 4> old_dest,
            std::span<const uint32_t, 4> new_src,
            std::span<const uint32_t, 4> new_dest)
        {
            if (fragoff > chksumoff || payload.size() < chksumoff - fragoff + 2)
                return;

            auto &check = *reinterpret_cast<uint16_t *>(payload.data() + chksumoff - fragoff);

            // Unlike UDP in IPv4, in IPv6 the UDP checksum is always required, thus we don't
            // special-case it being set to 0x0000 here as we do for IPv4 UDP.

            check = update_ipv6_checksum(check, old_src, old_dest, new_src, new_dest);

            // With 1's complement, 0xffff is -0 but that can never actually appear in a checksum
            // with any non-zero bytes (which will always be present here), so this corrects it to
            // the proper 0x000 (+0) value that it should have:
            if (check == 0xFFff)
                check = 0x0000;
        }

    }  // namespace utils

    uint16_t fold_csum(uint32_t csum)
    {
        auto sum = csum;
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        return static_cast<uint16_t>(~sum);
    }

#if 0
    // Updates a TCPv6 or UDPv6 checksum fo
    uint16_t ipv6_checksum(
        const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint8_t proto, uint32_t sum)
    {
        uint32_t csum = sum;

        auto *s32 = reinterpret_cast<const uint32_t *>(saddr->s6_addr);
        for (size_t i = 0; i < 4; ++i)
        {
            auto &val = s32[i];
            csum += val;
            csum += (csum < val);
        }

        auto *d32 = reinterpret_cast<const uint32_t *>(daddr->s6_addr);
        for (size_t i = 0; i < 4; ++i)
        {
            auto &val = d32[i];
            csum += val;
            csum += (csum < val);
        }

        uint32_t ulen = htonl(len);
        uint32_t uproto = htonl(proto);

        csum += ulen;
        csum += (csum < ulen);

        csum += uproto;
        csum += (csum < uproto);

        return fold_csum(csum);
    }

    uint32_t tcp_checksum_ipv6(const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint32_t csum)
    {
        return ~ipv6_checksum_magic(saddr, daddr, len, IPPROTO_TCP, csum);
    }

    uint32_t udp_checksum_ipv6(const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint32_t csum)
    {
        return ~ipv6_checksum_magic(saddr, daddr, len, IPPROTO_UDP, csum);
    }
#endif
}  //  namespace srouter
