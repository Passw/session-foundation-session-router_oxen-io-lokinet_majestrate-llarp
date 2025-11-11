#pragma once

#include "address/types.hpp"
#include "question.hpp"
#include "rr.hpp"

#include <nlohmann/json_fwd.hpp>

#include <optional>

namespace srouter
{
    struct IPPacket;

    namespace dns
    {
        struct SRVData;

        struct Message
        {
            Message() = default;
            explicit Message(const Question& question);

            // Non-copyable; see clone() if you want a copy with just the questions.
            Message(const Message&) = delete;

            Message(Message&&) = default;

            // Clones the message with question/flags/edns response data, but with no answers
            Message clone() const;

            nlohmann::json ToJSON() const;

            static constexpr auto DEFAULT_ANSWER_TTL = 10s;

            // These two clear any answers that may have been added and then set the appropriate
            // flags for a NXDomain (i.e. authoritative reply that the requested thing does not
            // exist) or a ServFail (i.e. we don't know how to answer, maybe try someone else).
            void set_nx_reply();
            void set_serv_fail();

            // This clears any answers and sets the appropriate header flags for a BADCOOKIE
            // response.  Note that this is only valid when the message has `additional_edns` as
            // part of this error code value is carried in that additional RR data.
            void set_badcookie_flags();

            // Sets the RR name for future added entries, or resets it to default with nullopt.  The
            // default (if not called or reset) is to use the question's name value.  Once set, the
            // value persists for any added answers until this method is called again.
            void set_rr_name(std::optional<std::string> name);
            std::string_view get_rr_name() const
            {
                return rr_name_override ? *rr_name_override : questions.size() ? questions.front().qname : ""sv;
            }

            void add_nodata_reply();

            void add_cname_reply(std::string_view name, std::chrono::seconds ttl = DEFAULT_ANSWER_TTL);

            // Adds an 'IN A' reply containing the given ipv4 address
            void add_reply(const ipv4& addr, std::chrono::seconds ttl = DEFAULT_ANSWER_TTL);
            // Adds an 'IN AAAA' reply containing the given ipv6 address
            void add_reply(const ipv6& addr, std::chrono::seconds ttl = DEFAULT_ANSWER_TTL);

            void add_reply(const SRVData& srv, std::chrono::seconds ttl = DEFAULT_ANSWER_TTL);

            void add_txt_reply(std::string_view value, std::chrono::seconds ttl = DEFAULT_ANSWER_TTL);

            void add_ptr_reply(std::string_view name, std::chrono::seconds ttl = DEFAULT_ANSWER_TTL);

            std::vector<std::byte> encode() const;

            // Parses a question Message from the given buf, removing the question from the prefix
            // of buf.  `server_cookie_secret` and `client_addr` contains information needed for DNS
            // cookie handling; `server_cookie_secret` is something derived from the SR private key
            // seed + startup time, while client_addr is the raw bytes of the IP address (4 or 16
            // bytes for IPv4/IPv6, respectively).
            static std::optional<Message> extract_question(
                std::span<const std::byte>& buf,
                std::span<const std::byte, 16> server_cookie_secret,
                std::span<const std::byte> client_addr);

            std::string to_string() const;

            uint16_t hdr_id;
            uint16_t hdr_fields;

            std::vector<Question> questions;
            std::vector<std::unique_ptr<ResourceRecord>> answers;

            // Currently unused:
            // std::vector<ResourceRecord> authorities;
            // std::vector<ResourceRecord> additional;

            // Currently the only additional record we do anything with is the OPT section for
            // enabling EDNS (most significantly for allowing large DNS packets)
            std::optional<PRR_EDNS> additional_edns;

            std::optional<std::string> rr_name_override;

          private:
            void add_reply(RRClass cls, RRType type, std::vector<std::byte> data, std::chrono::seconds ttl);
        };

    }  // namespace dns

}  // namespace srouter
