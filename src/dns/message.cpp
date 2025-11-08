#include "message.hpp"

#include "dns.hpp"
#include "encode.hpp"
#include "net/ip_packet.hpp"
#include "srv_data.hpp"
#include "util/logging.hpp"

#include <nlohmann/json.hpp>
#include <oxenc/endian.h>

#include <array>
#include <ranges>

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
        // Don't copy answers, or rr_name_override (which is just an intermediate answers helper)
        return c;
    }

    std::vector<std::byte> Message::encode() const
    {
        // TODO FIXME: We currently aren't respect the EDNS bit, and that means our maximum message
        // size is 512 bytes.  We should support EDNS (by checking and setting the appropriate flag
        // in `additional`), in which case 1232 becomes the (practical) maximum.
        //
        // Basically:
        // - if the client supports EDNS it sets the size in an additional flag
        // - we can then go up to whichever of that size or 1232 is smaller.
        // - we set the pseudo-RR in the additional flags section of the response.

        std::vector<std::byte> tmp;
        tmp.resize(512);

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
            static_cast<uint16_t>(0 /*additional.size()*/));

        // if (auto written = thing.encode(buf))
        //{
        //     buf = buf.subspan(written);
        //     return true;
        // }

        for (const auto& question : questions)
            question.encode(buf, prev_names, buf_offset);

        for (auto& a : answers)
            a->encode(buf, prev_names, buf_offset);

        // Trim the excess:
        tmp.resize(tmp.size() - buf.size());

        return tmp;
    }

    std::optional<Message> Message::extract(std::span<const std::byte>& buf)
    {
        auto maybe = std::make_optional<Message>();
        auto& m = *maybe;
        uint16_t qd_count, an_count, ns_count, ar_count;
        if (!extract_ints(buf, m.hdr_id, m.hdr_fields, qd_count, an_count, ns_count, ar_count))
        {
            maybe.reset();
            return maybe;
        }
        m.questions.resize(qd_count);
        m.answers.resize(an_count);
        // Ignore these:
        // m.authorities.resize(ns_count);
        // m.additional.resize(ar_count);

        for (auto& q : m.questions)
        {
            if (!q.extract(buf))
            {
                log::debug(logcat, "failed to decode question");
                maybe.reset();
                return maybe;
            }
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
        if (questions.size())
        {
            answers.clear();
            // authorities.clear();
            // additional.clear();

            // authorative response with recursion available
            hdr_fields |= reply_flags;
            // don't allow recursion on this request
            hdr_fields &= ~flags_RD;
            hdr_fields |= flags_RCODENxDomain;
        }
    }

    void Message::set_serv_fail()
    {
        if (questions.size())
        {
            hdr_fields |= flags_RCODEServFail;
            // authorative response with recursion available
            hdr_fields |= flags_QR | flags_AA | flags_RA;
            // don't allow recursion on this request
            hdr_fields &= ~flags_RD;
        }
    }

}  // namespace srouter::dns
