#include "question.hpp"

#include "address/address.hpp"
#include "dns.hpp"
#include "encode.hpp"
#include "util/logging.hpp"
#include "util/logging/buffer.hpp"
#include "util/str.hpp"

#include <nlohmann/json.hpp>

namespace srouter::dns
{
    static auto logcat = log::Cat("dns");

    Question::Question(std::string name, RRType type) : qname{std::move(name)}, qtype{type}, qclass{RRClass::IN}
    {
        if (qname.empty())
            throw std::invalid_argument{"qname cannot be empty"};
    }

    size_t Question::encode(std::span<std::byte> buf) const
    {
        auto orig = buf;
        if (!write_name_into(buf, qname))
            return 0;
        if (!write_ints_into(buf, static_cast<uint16_t>(qtype), static_cast<uint16_t>(qclass)))
            return 0;
        return orig.size() - buf.size();
    }

    bool Question::extract(std::span<const std::byte>& buf)
    {
        auto name = extract_name(buf);
        if (!name)
        {
            log::warning(logcat, "Failed to decode name from dns query");
            return false;
        }

        uint16_t qtype_code, qclass_code;
        if (!extract_ints(buf, qtype_code, qclass_code))
        {
            log::warning(logcat, "Failed to decode type and class from dns query");
            return false;
        }

        qname = std::move(*name);
        qtype = static_cast<RRType>(qtype_code);
        qclass = static_cast<RRClass>(qclass_code);
        return true;
    }

    nlohmann::json Question::ToJSON() const
    {
        return nlohmann::json{{"qname", qname}, {"qtype", qtype}, {"qclass", qclass}};
    }

    std::string_view Question::name() const
    {
        std::string_view name{qname};
        if (name.ends_with('.'))
            name.remove_suffix(1);
        return name;
    }

    bool Question::has_tld(std::string_view tld) const
    {
        if (tld.starts_with('.'))
            tld.remove_prefix(1);
        auto qnodot = name();
        return qnodot.size() > tld.size() && qnodot.ends_with(tld) && qnodot[qnodot.size() - tld.size() - 1] == '.';
    }

    std::string Question::to_string() const
    {
        return "DNSQuestion:[ qname:{} | qtype:{} | qclass:{} ]"_format(
            qname, static_cast<uint16_t>(qtype), static_cast<uint16_t>(qclass));
    }
}  // namespace srouter::dns
