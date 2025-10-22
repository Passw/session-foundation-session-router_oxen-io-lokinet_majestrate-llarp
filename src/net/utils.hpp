#pragma once

#include "address/types.hpp"

namespace srouter
{
    inline constexpr uint32_t ipv6_flowlabel_mask = 0b0000'0000'0000'1111'1111'1111'1111'1111;

    inline constexpr size_t ICMP_HEADER_SIZE{8};

    namespace utils
    {
        uint16_t ip_checksum(const uint8_t *buf, size_t sz);

        // Parameters:
        //  - old_sum : old checksum (in network order)
        //  - old_{src,dest} : old src and dest IP's (in network order)
        //  - new_{src,dest} : new src and dest IP's
        //
        // Returns:
        //  - uint16_t : new checksum (in network order)
        uint16_t update_ipv4_checksum(
            uint16_t old_sum, uint32_t old_src, uint32_t old_dest, const ipv4 &new_src, const ipv4 &new_dest);

        uint16_t update_ipv4_tcp_checksum(
            uint16_t old_sum, uint32_t old_src, uint32_t old_dest, const ipv4 &new_src, const ipv4 &new_dest);

        uint16_t update_ipv4_udp_checksum(
            uint16_t old_sum, uint32_t old_src, uint32_t old_dest, const ipv4 &new_src, const ipv4 &new_dest);

        uint16_t update_ipv6_checksum(
            uint16_t old_sum,
            std::span<const uint32_t, 4> old_src,
            std::span<const uint32_t, 4> old_dest,
            std::span<const uint32_t, 4> new_src,
            std::span<const uint32_t, 4> new_dest);

        // Mutates the payload checksum to match a change of {old_src,old_dest} ->
        // {new_src,new_dest}
        void update_ipv6_proto_checksum(
            std::span<std::byte> payload,
            size_t fragoff,
            size_t chksumoff,
            std::span<const uint32_t, 4> old_src,
            std::span<const uint32_t, 4> old_dest,
            std::span<const uint32_t, 4> new_src,
            std::span<const uint32_t, 4> new_dest);

    }  // namespace utils

    /*
    uint32_t tcp_checksum_ipv6(const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint32_t csum);

    uint32_t udp_checksum_ipv6(const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint32_t csum);
    */

}  //  namespace srouter
