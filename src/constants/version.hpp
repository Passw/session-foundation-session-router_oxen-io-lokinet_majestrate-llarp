#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace srouter
{
    // Given a full Session Router version of: session-router-1.2.3-abc these are:
    extern const std::array<uint8_t, 3> VERSION;  // [1, 2, 3]
    extern const std::string VERSION_TAG;         // "abc"
    extern const std::string VERSION_FULL;        // "session-router-1.2.3-abc"
}  // namespace srouter
