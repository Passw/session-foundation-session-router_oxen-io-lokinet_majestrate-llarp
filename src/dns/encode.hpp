#pragma once

#include "address/types.hpp"

#include <oxenc/endian.h>

#include <concepts>
#include <optional>
#include <string>
#include <utility>

namespace srouter::dns
{
    /// Writes the encoded version of DNS name `name` into buf, and returns how many bytes of buf
    /// were written.  If buf is too small to store the encoded name, returns 0.
    size_t encode_name(std::span<std::byte> buf, std::string_view name);

    /// Same as encode_name, except that instead of returning the written size, on success it mutates the span
    /// to drop the written prefix.  Returns true (and prefix-drops the written part of the span) on success,
    /// false on failure.  Note that the failure case can still partially write into span.
    bool write_name_into(std::span<std::byte>& buf, std::string_view name);

    /// decode name from buffer, mutating the buffer to begin just past the extracted name.  Return
    /// nullopt (without mutating buf) on failure.
    std::optional<std::string> extract_name(std::span<const std::byte>& buf);

    /// Encodes an integer in big-endian order into the buffer, mutating the span to start just
    /// after the written integer.  Returns true on success, false if the span was too small.
    template <std::unsigned_integral T>
    bool write_int_into(std::span<std::byte>& buf, T value)
    {
        if (buf.size() < sizeof(T))
            return false;
        oxenc::write_host_as_big(value, buf.data());
        buf = buf.subspan(sizeof(T));
        return true;
    }

    // Calls write_int_info multiple times with the given integers.  Returns true (and modifies buf)
    // if all success.  If any fail then false is returned and buf is left unchanged.
    template <std::unsigned_integral... T>
    bool write_ints_into(std::span<std::byte>& buf, T... values)
    {
        if (buf.size() < (0 + ... + sizeof(T)))
            return false;
        ((void)write_int_into(buf, values), ...);
        return true;
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

    // Takes some object T with an `size_t encode(buf)` function (such as various classes in this
    // dns code) and attempts to call it with the given buffer.  If it returns success (non-0) then
    // this mutates `buf` to skip the written data and returns true; on failure it returns false.
    template <typename T>
    bool encode_into(std::span<std::byte>& buf, const T& thing)
    {
        if (auto written = thing.encode(buf))
        {
            buf = buf.subspan(written);
            return true;
        }
        return false;
    }

    // Writes encoded rr data into buf, mutating buf to point beyond the written data.  Returns
    // false (without mutating buf) if buf is too short; true on success.
    bool write_rdata_into(std::span<std::byte>& buf, std::span<const std::byte> rdata);
    // Extracts encoded rr data from buf, mutating buf to point beyond the extracted data.  Returns
    // nullopt (without mutating buf) on error, the vector of decoded data on success.
    std::optional<std::vector<std::byte>> extract_rdata(std::span<const std::byte>& buf);

    std::optional<std::variant<ipv4, ipv6>> decode_ptr(std::string_view name);

}  // namespace srouter::dns
