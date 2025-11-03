#pragma once

#include "serialize.hpp"

namespace srouter::dns
{
    using QType_t = uint16_t;
    using QClass_t = uint16_t;

    struct Question : public Serialize
    {
        Question() = default;

        explicit Question(std::string name, QType_t type);

        Question(Question&& other);
        Question(const Question& other);

        bool Encode(buffer_t* buf) const override;

        bool Decode(buffer_t* buf) override;

        std::string to_string() const;

        bool operator==(const Question& other) const
        {
            return qname == other.qname && qtype == other.qtype && qclass == other.qclass;
        }

        std::string qname;
        QType_t qtype;
        QClass_t qclass;

        /// determine if we match a name
        bool IsName(const std::string& other) const;

        /// is the name [something.]localhost.sesh.  (or .loki)?
        bool IsLocalhost() const;

        /// return true if we have a subdomain in this question
        bool HasSubdomain() const;

        /// get subdomain(s), if any, from qname
        std::string Subdomain() const;

        /// return qname with no trailing .
        std::string Name() const;

        /// Returns true if the qname ends with a dot followed by the given `tld` value.  (`tld`
        /// can, but does not require, the leading dot, i.e. ".sesh" and "sesh" are equivalent).
        bool HasTLD(std::string_view tld) const;

        nlohmann::json ToJSON() const override;
    };
}  // namespace srouter::dns
