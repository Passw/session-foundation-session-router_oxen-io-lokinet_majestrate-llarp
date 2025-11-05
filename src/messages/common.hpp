#pragma once

#include "contact/relay_contact.hpp"
#include "crypto/crypto.hpp"
#include "path/transit_hop.hpp"
#include "util/buffer.hpp"
#include "util/logging.hpp"

#include <oxenc/bt_producer.h>

namespace srouter::messages
{
    inline constexpr auto STATUS_KEY = "!"sv;
    std::string serialize_status_response(std::string_view value);

    constexpr auto STATUS_OK = "OK"sv;
    constexpr auto STATUS_TIMEOUT = "TIMEOUT"sv;
    constexpr auto STATUS_ERROR = "ERROR"sv;
    constexpr auto STATUS_NOT_FOUND = "NOT FOUND"sv;

    extern const std::string TIMEOUT_RESPONSE;
    extern const std::string ERROR_RESPONSE;
    extern const std::string OK_RESPONSE;
    extern const std::string NOT_FOUND_RESPONSE;
}  // namespace srouter::messages
