#pragma once

#include <oxen/quic/format.hpp>

namespace srouter
{
    using oxen::quic::buffer_printer;

    // Deferred convertion of a value to hex for use in log statements, e.g. instead of
    //     log::debug(logcat, "blah blah {}", oxenc::to_hex(value))
    // you use:
    //     log::debug(logcat, "blah blah {}", hex_printer(value))
    // to get the same output if the log statement is shown, and save the conversion (and string
    // allocation) when the statement isn't shown at the current log level.
    struct hex_printer
    {
      private:
        std::span<const std::byte> buf;

      public:
        // string_view, C str literals, const string&:
        explicit hex_printer(std::string_view data) : buf{oxen::quic::reinterpret_span<const std::byte>(data)} {}

        // *Not* constructable from a string temporary because we only hold a view and do not take
        // ownership, and so the string will not survive until print time.
        explicit hex_printer(std::string&& buf) = delete;

        // From byte span:
        explicit hex_printer(std::span<const std::byte> data) : buf{data} {}
        explicit hex_printer(std::span<const unsigned char> data)
            : buf{oxen::quic::reinterpret_span<const std::byte>(data)}
        {}

        std::string to_string() const;
        static constexpr bool to_string_formattable = true;
    };

}  // namespace srouter
