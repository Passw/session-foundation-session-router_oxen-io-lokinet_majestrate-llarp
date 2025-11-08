#pragma once

#include <cstdint>

namespace srouter::dns
{
    constexpr uint16_t flags_QR = 1 << 15;
    constexpr uint16_t flags_AA = 1 << 10;
    constexpr uint16_t flags_TC = 1 << 9;
    constexpr uint16_t flags_RD = 1 << 8;
    constexpr uint16_t flags_RA = 1 << 7;
    constexpr uint16_t flags_RCODENxDomain = 3;
    constexpr uint16_t flags_RCODEServFail = 2;
    constexpr uint16_t flags_RCODENoError = 0;

}  // namespace srouter::dns
