#include "message.hpp"

#include "dns.hpp"
#include "encode.hpp"
#include "net/ip_packet.hpp"
#include "srv_data.hpp"
#include "util/logging.hpp"

#include <nlohmann/json.hpp>
#include <oxenc/endian.h>

#include <array>

namespace srouter::dns
{
    static auto logcat = log::Cat("dns");

    Message::Message(const Question& question) : hdr_id{0}, hdr_fields{} { questions.push_back(question); }

    size_t Message::encode(std::span<std::byte> buf) const
    {
        auto orig = buf.size();
        if (!write_ints_into(
                buf,
                hdr_id,
                hdr_fields,
                static_cast<uint16_t>(questions.size()),
                static_cast<uint16_t>(answers.size()),
                static_cast<uint16_t>(authorities.size()),
                static_cast<uint16_t>(additional.size())))
            return 0;

        for (const auto& question : questions)
            if (!encode_into(buf, question))
                return 0;

        for (auto& a : answers)
            if (!encode_into(buf, a))
                return 0;

        return orig - buf.size();
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
        for (auto* as : {&m.answers, &m.authorities, &m.additional})
            if (!as->empty())
                log::debug(logcat, "Ignoring answer/authorities/additional sections in dns Message");

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
            ans.push_back(a.ToJSON());
        return result;
    }

    std::vector<std::byte> Message::encode() const
    {
        std::vector<std::byte> tmp;
        tmp.resize(1500);
        auto size = encode(tmp);
        if (size == 0)
            throw std::runtime_error("cannot encode dns message");
        tmp.resize(size);
        return tmp;
    }

    void Message::add_serv_fail()
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

    static constexpr uint16_t reply_flags = flags_QR | flags_AA | flags_RA;

    void Message::add_reply(ipv4 addr, std::chrono::seconds ttl)
    {
        std::vector<std::byte> a;
        a.resize(4);
        oxenc::write_host_as_big(addr.addr, a.data());
        add_reply(RRClass::IN, RRType::A, std::move(a), ttl);
    }

    void Message::add_reply(ipv6 addr, std::chrono::seconds ttl)
    {
        std::vector<std::byte> aaaa;
        aaaa.resize(16);
        oxenc::write_host_as_big(addr.hi, aaaa.data());
        oxenc::write_host_as_big(addr.lo, aaaa.data() + 8);
        return add_reply(RRClass::IN, RRType::AAAA, std::move(aaaa), ttl);
    }

    void Message::set_rr_name(std::optional<std::string> name) { rr_name_override = std::move(name); }

    void Message::add_reply(RRClass cls, RRType type, std::vector<std::byte> data, std::chrono::seconds ttl)
    {
        if (questions.empty())
            return;

        hdr_fields |= reply_flags;

        auto& ans = answers.emplace_back();
        ans.rr_name = get_rr_name();
        ans.rr_type = type;
        ans.rr_class = cls;
        ans.ttl = ttl;
        ans.rData = std::move(data);
    }

    void Message::add_nodata_reply()
    {
        if (not questions.empty())
            hdr_fields |= reply_flags;
    }

    void Message::add_cname_reply(std::string_view name, std::chrono::seconds ttl)
    {
        std::array<std::byte, 512> tmp;
        if (auto len = encode_name(tmp, name))
            add_reply(RRClass::IN, RRType::CNAME, std::vector<std::byte>{tmp.data(), tmp.data() + len}, ttl);
        else
            log::error(logcat, "Failed to encode CNAME value {}", name);
    }

    void Message::add_ptr_reply(std::string_view name, std::chrono::seconds ttl)
    {
        std::array<std::byte, 512> tmp;
        if (auto len = encode_name(tmp, name))
            add_reply(RRClass::IN, RRType::PTR, std::vector<std::byte>{tmp.data(), tmp.data() + len}, ttl);
        else
            log::error(logcat, "Failed to encode PTR value {}", name);
    }

    void Message::add_reply(const SRVData& srv, std::chrono::seconds ttl)
    {
        std::array<std::byte, 512> tmp;
        std::span<std::byte> remaining{tmp};
        if (!write_ints_into(remaining, srv.priority, srv.weight, srv.port))
            return;
        if (!write_name_into(remaining, srv.target))
            return;

        add_reply(
            RRClass::IN,
            RRType::SRV,
            std::vector<std::byte>{tmp.data(), tmp.data() + tmp.size() - remaining.size()},
            ttl);
    }

    void Message::add_txt_reply(std::string_view txt, std::chrono::seconds ttl)
    {
        std::array<std::byte, 1024> tmp;
        std::span<std::byte> remaining{tmp};
        while (!txt.empty())
        {
            auto piecelen = std::min(txt.size(), size_t{255});
            if (remaining.size() <= piecelen)
                throw std::length_error{"TXT record too big"};
            remaining.front() = static_cast<std::byte>(piecelen);
            std::memcpy(remaining.data() + 1, txt.data(), piecelen);
            txt.remove_prefix(piecelen);
            remaining = remaining.subspan(1 + piecelen);
        }

        add_reply(
            RRClass::IN,
            RRType::SRV,
            std::vector<std::byte>{tmp.data(), tmp.data() + tmp.size() - remaining.size()},
            ttl);
    }

    void Message::add_nx_reply()
    {
        if (questions.size())
        {
            answers.clear();
            authorities.clear();
            additional.clear();

            // authorative response with recursion available
            hdr_fields |= reply_flags;
            // don't allow recursion on this request
            hdr_fields &= ~flags_RD;
            hdr_fields |= flags_RCODENxDomain;
        }
    }

    std::string Message::to_string() const
    {
        return fmt::format(
            "[DNSMessage id={:x} fields={:x} questions={{{}}} answers={{{}}} authorities={{{}}} "
            "additional={{{}}}]",
            hdr_id,
            hdr_fields,
            fmt::join(questions, ","),
            fmt::join(answers, ","),
            fmt::join(authorities, ","),
            fmt::join(additional, ","));
    }

}  // namespace srouter::dns
