#pragma once

#include "rr.hpp"

#include <string>

namespace srouter::dns
{
    struct Question
    {
        Question() = default;
        Question(std::string name, RRType type);

        size_t encode(std::span<std::byte> buf) const;

        bool extract(std::span<const std::byte>& buf);

        std::string to_string() const;
        static constexpr bool to_string_formattable = true;

        bool operator==(const Question& other) const = default;

        std::string qname;
        RRType qtype;
        RRClass qclass;

        /// return qname with no trailing .
        std::string_view name() const;

        /// Returns true if the qname ends with a dot followed by the given `tld` value.  (`tld`
        /// can, but does not require, the leading dot, i.e. ".sesh" and "sesh" are equivalent).
        bool has_tld(std::string_view tld) const;

        nlohmann::json ToJSON() const;
    };
}  // namespace srouter::dns
