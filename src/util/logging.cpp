#include "logging.hpp"

#include "logging/buffer.hpp"

#include <oxen/log/catlogger.hpp>
#include <oxen/log/ring_buffer_sink.hpp>
#include <oxenc/hex.h>

namespace srouter
{

    log::CategoryLogger log_global = log::Cat("session-router");

    std::shared_ptr<log::RingBufferSink> logRingBuffer{};

    std::string hex_printer::to_string() const { return oxenc::to_hex(buf); }

}  // namespace srouter
