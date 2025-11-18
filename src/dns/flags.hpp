#pragma once

#include <cstdint>

namespace srouter::dns
{
    constexpr uint16_t flags_QR = 1 << 15;
    constexpr uint16_t flags_AA = 1 << 10;
    constexpr uint16_t flags_TC = 1 << 9;
    constexpr uint16_t flags_RD = 1 << 8;
    constexpr uint16_t flags_RA = 1 << 7;
    constexpr uint16_t flags_AD = 1 << 5;
    constexpr uint16_t flags_CD = 1 << 4;

    constexpr uint16_t flags_RCODE_mask = ~uint16_t{0b1111};

    constexpr uint16_t RCODE_Refused = 5;
    constexpr uint16_t RCODE_NxDomain = 3;
    constexpr uint16_t RCODE_ServFail = 2;
    constexpr uint16_t RCODE_FormErr = 1;
    constexpr uint16_t RCODE_NoError = 0;

    inline constexpr uint16_t set_rcode(uint16_t flags, uint16_t rcode) { return (flags & flags_RCODE_mask) | rcode; }

}  // namespace srouter::dns
