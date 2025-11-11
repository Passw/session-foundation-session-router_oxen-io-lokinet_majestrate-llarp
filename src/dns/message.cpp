#include "message.hpp"

#include "dns.hpp"
#include "encode.hpp"
#include "net/ip_packet.hpp"
#include "srv_data.hpp"
#include "util/logging.hpp"

#include <nlohmann/json.hpp>
#include <oxenc/endian.h>
#include <sodium/crypto_shorthash_siphash24.h>

#include <array>
#include <chrono>
#include <ranges>
#include <stdexcept>

namespace srouter::dns
{
    static auto logcat = log::Cat("dns");

    Message::Message(const Question& question) : hdr_id{0}, hdr_fields{} { questions.push_back(question); }

    Message Message::clone() const
    {
        Message c;
        c.hdr_id = hdr_id;
        c.hdr_fields = hdr_fields;
        c.questions = questions;
        c.additional_edns = additional_edns;
        // Don't copy answers, or rr_name_override (which is just an intermediate answers helper)
        return c;
    }

    std::vector<std::byte> Message::encode() const
    {
        std::vector<std::byte> tmp;
        // If the client signalled EDNS support then we can use a larger payload, otherwise DNS is
        // limited to 512 bytes.
        tmp.resize(additional_edns ? additional_edns->max_payload() : 512);

        prev_names_t prev_names;
        std::span<std::byte> buf{tmp};
        uint16_t buf_offset = 0;

        buf_offset += write_ints_into(
            buf,
            hdr_id,
            hdr_fields,
            static_cast<uint16_t>(questions.size()),
            static_cast<uint16_t>(answers.size()),
            static_cast<uint16_t>(0 /*authorities.size()*/),
            static_cast<uint16_t>(additional_edns ? 1 : 0 /*additional.size()*/));

        for (const auto& question : questions)
            question.encode(buf, prev_names, buf_offset);

        for (auto& a : answers)
            a->encode(buf, prev_names, buf_offset);

        if (additional_edns)
            additional_edns->encode(buf, prev_names, buf_offset);

        // Trim the excess:
        tmp.resize(tmp.size() - buf.size());

        return tmp;
    }

    static std::array<std::byte, 24> make_server_cookie(
        std::span<const std::byte, 8> client_cookie,
        std::span<const std::byte> client_ip,
        std::span<const std::byte, 16> server_cookie_secret,
        std::chrono::sys_seconds ts = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()))
    {
        assert(client_ip.size() == 4 || client_ip.size() == 16);

        static_assert(server_cookie_secret.size() == crypto_shorthash_siphash24_KEYBYTES);

        std::array<std::byte, 24> cookie;
        auto ccookie = std::span{cookie}.first<8>();
        auto scookie = std::span{cookie}.last<16>();
        std::memcpy(ccookie.data(), client_cookie.data(), 8);

        // The first 8 bytes of the server cookie (as per RFC 9018) are:
        // - version (always 1)
        // - three reserved bytes
        // - 4-byte, uint32 unix timestamp
        scookie[0] = std::byte{1};  // Version
        scookie[1] = std::byte{0};  // -
        scookie[2] = std::byte{0};  // - reserved
        scookie[3] = std::byte{0};  // -
        auto ts_val = static_cast<uint32_t>(ts.time_since_epoch().count());
        oxenc::write_host_as_big(ts_val, &scookie[4]);

        // The last 8 bytes of the server cookie are a hash of 8-byte client
        // cookie, then the above 8 bytes server cookie fields, then the
        // 4- or 16-byte client IP (in network order notation).
        std::array<unsigned char, 32> hash_data{{0}};
        std::memcpy(hash_data.data(), ccookie.data(), 8);
        std::memcpy(hash_data.data() + 8, scookie.data(), 8);
        std::memcpy(hash_data.data() + 16, client_ip.data(), client_ip.size());
        crypto_shorthash_siphash24(
            reinterpret_cast<unsigned char*>(scookie.data() + 8),
            hash_data.data(),
            16 + client_ip.size(),
            reinterpret_cast<const unsigned char*>(server_cookie_secret.data()));

        return cookie;
    }

    std::optional<Message> Message::extract_question(
        std::span<const std::byte>& buf,
        std::span<const std::byte, 16> server_cookie_secret,
        std::span<const std::byte> client_ip)
    {
        if (client_ip.size() != 4 && client_ip.size() != 16)
            throw std::logic_error{"Invalid client IP for Message::extract_question"};
        auto maybe = std::make_optional<Message>();
        auto& m = *maybe;
        uint16_t qd_count, an_count, ns_count, ar_count;
        if (!extract_ints(buf, m.hdr_id, m.hdr_fields, qd_count, an_count, ns_count, ar_count))
        {
            maybe.reset();
            return maybe;
        }
        m.questions.resize(qd_count);
        // Ignore these:
        // m.answers.resize(an_count);
        // m.authorities.resize(ns_count);
        // m.additional.resize(ar_count);

        try
        {
            for (auto& q : m.questions)
                if (!q.extract(buf))
                    throw std::invalid_argument{"invalid question"};

            // Skip any answers or authority records:
            for (uint16_t i = 0; i < an_count; i++)
                if (!ParsedRR::extract(buf))
                    throw std::invalid_argument{"invalid answer RR"};
            for (uint16_t i = 0; i < ns_count; i++)
                if (!ParsedRR::extract(buf))
                    throw std::invalid_argument{"invalid authority RR"};

            // In the additional section we look for an EDNS entry, and skip anything else:
            for (uint16_t i = 0; i < ar_count; i++)
            {
                static_assert(crypto_shorthash_siphash24_KEYBYTES == 16);
                auto a_rr = ParsedRR::extract(buf);
                if (!a_rr)
                    throw std::invalid_argument{"invalid additional RR"};
                if (a_rr->name != "." || a_rr->rr_type != RRType::OPT)
                {
                    continue;
                }

                if (m.additional_edns)
                    throw std::invalid_argument{"found invalid multiple additional OPT records"};

                auto max_payload = static_cast<uint16_t>(a_rr->rr_class);
                m.additional_edns.emplace(std::min<uint16_t>(max_payload, 1232));

                std::optional<std::vector<std::byte>> cookie;
                for (auto optbuf = a_rr->rdata; !optbuf.empty();)
                {
                    if (optbuf.size() < 4)
                        throw std::invalid_argument{"additional OPT data section too small"};
                    auto opt_code = oxenc::load_big_to_host<uint16_t>(optbuf.data());
                    auto opt_len = oxenc::load_big_to_host<uint16_t>(optbuf.data() + 2);
                    optbuf = optbuf.subspan(4);
                    if (opt_len > optbuf.size())
                        throw std::invalid_argument{"additional OPT option value length too small"};
                    auto value = optbuf.subspan(0, opt_len);
                    optbuf = optbuf.subspan(opt_len);

                    if (opt_code == PRR_EDNS::OPT_COOKIE)
                    {
                        if (m.additional_edns->cookie)
                            throw std::invalid_argument{"Duplicate OPT client cookies"};

                        if (value.size() == 8)
                        {
                            // This is the client sending a new cookie, requesting a new server
                            // cookie (i.e. because it doesn't currently have one).

                            m.additional_edns->cookie =
                                make_server_cookie(value.first<8>(), client_ip, server_cookie_secret);
                        }
                        else if (value.size() == 24)
                        {
                            // This is the client sending its cookie along with a previously
                            // obtained server cookie for that client cookie, so we are supposed
                            // to validate it.
                            auto ccookie = value.first<8>();
                            auto scookie = value.last<16>();

                            std::chrono::sys_seconds ts{
                                std::chrono::seconds{oxenc::load_big_to_host<uint32_t>(&scookie[4])}};

                            auto expected = make_server_cookie(ccookie, client_ip, server_cookie_secret, ts);
                            bool bad_cookie = std::memcmp(value.data(), expected.data(), 24) != 0;

                            auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());

                            if (!bad_cookie && ts >= now - 30min && ts <= now + 5min)
                                // Cookie is good and the timestamp in it is close to now, so the
                                // cookie stays as-is.
                                std::memcpy(m.additional_edns->cookie.emplace().data(), value.data(), 24);

                            else
                            {
                                // If the cookie timestamp is too far away then it is a badcookie
                                // failure.  (We don't have to worry about client clock skew because
                                // supposedly *we* issued this with the timestamp in it).
                                if (bad_cookie || ts < now - 1h || ts > now + 5min)
                                {
                                    // When this is set we'll send a proper bad cookie response
                                    // immediately after parsing:
                                    m.additional_edns->bad_cookie = true;
                                    // Extended rcode is, um, a wee bit hacky: we put the high 8
                                    // bits of the 12-bit error code into the OPT TTL field, and
                                    // then continue to use the 4-bit RCODE for the bottom 4 bits.
                                    m.additional_edns->ttl =
                                        std::chrono::seconds{(uint32_t{PRR_EDNS::EXT_RCODE_BADCOOKIE} >> 4) << 24};
                                    // (The other bytes are all 0 values)
                                }

                                // else it's valid, just a little bit (but not too) old and they are
                                // due for a new cookie.

                                // In either of the above cases, we give the client a new cookie
                                // to use, with an updated new timestamp
                                m.additional_edns->cookie =
                                    make_server_cookie(ccookie, client_ip, server_cookie_secret, now);
                            }
                        }
                        // Else we have an unparseable/non-understood cookie, and so we are supposed
                        // to ignore the option and discard the cookie data.
                    }
                }
            }
        }
        catch (const std::exception& e)
        {
            log::debug(logcat, "failed to parse DNS message: {}", e.what());
            maybe.reset();
        }

        return maybe;
    }

    nlohmann::json Message::ToJSON() const
    {
        auto result = nlohmann::json{{"id", hdr_id}, {"fields", hdr_fields}};
        auto& ques = (result["questions"] = nlohmann::json::array());
        auto& ans = (result["answers"] = nlohmann::json::array());
        for (const auto& q : questions)
            ques.push_back(q.ToJSON());
        for (const auto& a : answers)
            ans.push_back(a->ToJSON());
        return result;
    }

    void Message::set_rr_name(std::optional<std::string> name) { rr_name_override = std::move(name); }

    // TODO FIXME: "RA" means we advertise that we support recursion, but we should only do that
    // when we have an upstream DNS server available.  (This TODO is also in server.cpp)
    static constexpr uint16_t reply_flags = flags_QR | flags_AA | flags_RA;

    void Message::add_nodata_reply()
    {
        if (not questions.empty())
            hdr_fields |= reply_flags;
    }

    template <std::derived_from<ResourceRecord> RR, typename... Args>
    void make_reply(Message& m, std::chrono::seconds ttl, Args&&... args)
    {
        if (m.questions.empty())
            return;

        m.hdr_fields |= reply_flags;

        m.answers.push_back(std::make_unique<RR>(std::string{m.get_rr_name()}, ttl, std::forward<Args>(args)...));
    }

    void Message::add_reply(const ipv4& addr, std::chrono::seconds ttl) { make_reply<RR_A>(*this, ttl, addr); }

    void Message::add_reply(const ipv6& addr, std::chrono::seconds ttl) { make_reply<RR_AAAA>(*this, ttl, addr); }

    void Message::add_cname_reply(std::string_view name, std::chrono::seconds ttl)
    {
        make_reply<RR_CNAME>(*this, ttl, std::string{name});
    }

    void Message::add_ptr_reply(std::string_view name, std::chrono::seconds ttl)
    {
        make_reply<RR_PTR>(*this, ttl, std::string{name});
    }

    void Message::add_reply(const SRVData& srv, std::chrono::seconds ttl) { make_reply<RR_SRV>(*this, ttl, srv); }

    void Message::add_txt_reply(std::string_view txt, std::chrono::seconds ttl) { make_reply<RR_TXT>(*this, ttl, txt); }

    void Message::set_nx_reply()
    {
        answers.clear();
        // authorities.clear();
        // additional.clear();

        if (questions.size())
        {
            hdr_fields |= flags_RCODENxDomain;
            // authorative response with recursion available
            hdr_fields |= reply_flags;
        }
    }

    void Message::set_serv_fail()
    {
        answers.clear();

        if (questions.size())
        {
            hdr_fields |= flags_RCODEServFail;
            // authorative response with recursion available
            hdr_fields |= reply_flags;
            // A servfail is not an authoritative answer, so clear that bit:
            hdr_fields &= ~flags_AA;
        }
    }

}  // namespace srouter::dns
