#pragma once

#include "address/types.hpp"

#include <oxenc/endian.h>

#include <concepts>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace srouter::dns
{
    // Custom hasher to let us look up a string_view key in a string-keyed unordered map:
    struct transparent_string_hash
    {
        using is_transparent = void;
        [[nodiscard]] size_t operator()(std::string_view txt) const { return std::hash<std::string_view>{}(txt); }
    };

    using prev_names_t = std::unordered_map<std::string, uint16_t, transparent_string_hash, std::equal_to<>>;

    /// Writes the encoded version of DNS name `name` into buf, mutating buf to eliminate the
    /// written bytes.  Throws if buf is too small to store the encoded name.
    ///
    /// prev_names contains pointer values relative to the start of the message, used for name
    /// compression, and buf_offset contains the relative positive of the beginning of buf to the
    /// start of the message.  New names added here should be added into it so that later repeated
    /// names (or name suffixes) can use compression.
    ///
    /// These should normally be provided so that answers can compress names by pointing back into
    /// the question, but can be nullptr to disable tracking (such as when dealing with
    /// pre-compressed name data).
    void encode_name(std::span<std::byte>& buf, std::string_view name, prev_names_t* prev_names, uint16_t* buf_offset);

    /// Extracts the bytes making up an encoded name from the buffer, returning them and shortening
    /// buf by the extracted bytes.
    std::optional<std::span<const std::byte>> extract_name_data(std::span<const std::byte>& buf);

    /// decode name from buffer, mutating the buffer to begin just past the extracted name.  Return
    /// nullopt (without mutating buf) on failure.  Does not currently support compressed names (but
    /// those are not typically used in questions).
    std::optional<std::string> extract_name(std::span<const std::byte>& buf);

    /// Encodes an integer in big-endian order into the buffer, mutating the span to start just
    /// after the written integer.  Throws if buf is too small.  Returns sizeof(T) (i.e. the amount
    /// written into the buffer), for convenience.
    template <std::unsigned_integral T>
    size_t write_int_into(std::span<std::byte>& buf, T value)
    {
        if (buf.size() < sizeof(T))
            throw std::out_of_range{"Buffer too small"};
        oxenc::write_host_as_big(value, buf.data());
        buf = buf.subspan(sizeof(T));
        return sizeof(T);
    }

    // Calls write_int_info multiple times with the given integers.  Throws if the buffer is too
    // small.  Returns the total size of the given integers (i.e. the number of bytes written to
    // buf), for convenience.
    template <std::unsigned_integral... T>
    size_t write_ints_into(std::span<std::byte>& buf, T... values)
    {
        // NB: it's tempting to want to use `return (0 + ... + write_int_into())` here, but
        // left-to-right evaluation of + operands isn't guaranteed, and that could put things into
        // buf in the wrong order.  With , as used here it is guaranteed (similarly to || or &&).
        ((void)write_int_into(buf, values), ...);
        return (0 + ... + sizeof(T));
    }

    /// Extracts a big-endian integer of the given type from the buffer, mutating the span to start
    /// just after the extracted value.  Returns the integer on success, false if the buffer is too
    /// small to hold the requested integer type.
    template <std::unsigned_integral T>
    std::optional<T> extract_int(std::span<const std::byte>& buf)
    {
        if (buf.size() < sizeof(T))
            return std::nullopt;
        auto* p = buf.data();
        buf = buf.subspan(sizeof(T));
        return oxenc::load_big_to_host<T>(p);
    }

    // Extracts multiple ints at once, where each is extracted by a call to extract_int.  Returns
    // false if extraction fails (without mutating buf); otherwise writes all the values to the
    // given references, mutates buf, and returns true.
    template <std::unsigned_integral... T>
    bool extract_ints(std::span<const std::byte>& buf, T&... vals)
    {
        if (buf.size() < (0 + ... + sizeof(T)))
            return false;
        ((void)(vals = *extract_int<T>(buf)), ...);
        return true;
    }

    // Extracts encoded rr data from buf, mutating buf to point beyond the extracted data.  Returns
    // nullopt (without mutating buf) on error, the vector of decoded data on success.
    std::optional<std::vector<std::byte>> extract_rdata(std::span<const std::byte>& buf);

    std::optional<std::variant<ipv4, ipv6>> decode_ptr(std::string_view name);

}  // namespace srouter::dns
