#include "sns.hpp"

#include "util/str.hpp"

#include <string_view>

namespace srouter
{

    using namespace std::literals;

    bool is_valid_sns(std::string_view sns_name)
    {
        // TODO: Add support for .sesh SNS addresses, once they are a thing.
        if (not sns_name.ends_with(".loki"))
            return false;

        // strip off .loki suffix
        sns_name.remove_suffix(5);

        // ensure chars are sane
        for (const auto ch : sns_name)
        {
            if (ch == '-')
                continue;
            if (ch == '.')
                continue;
            if (ch >= 'a' and ch <= 'z')
                continue;
            if (ch >= '0' and ch <= '9')
                continue;
            return false;
        }

        // split into domain parts
        const auto parts = split(sns_name, ".");

        // get root domain
        const auto primaryName = parts.back();

        // Maximum name length: names with -s in them are obviously enough not plain pubkeys, so we
        // allow longer (partly to allow punycode); names without any dashes are capped at 32
        // characters so that they don't get visually close to masquerading as 52-char pubkeys.
        constexpr size_t MaxAlphanumNameLen = 32;
        constexpr size_t MaxDashedNameLen = 63;

        // check against sns name blacklist
        for (auto reserved : {"localhost"sv, "sesh"sv, "snode"sv, "loki"sv})
            if (primaryName == reserved)
                return false;

        // check for dashes: if there are none, then this is a relative plain name and anything up
        // to the max basic size (other than the above exceptions) is allowed.
        if (primaryName.find("-") == std::string_view::npos)
            return primaryName.size() <= MaxAlphanumNameLen;

        // Otherwise we have dashes in the name, which are a bit more restricted:

        // No dashes at end or beginning:
        if (primaryName.starts_with('-') or primaryName.ends_with('-'))
            return false;

        // Not too long (63 chars is a DNS limit)
        if (primaryName.size() > MaxDashedNameLen)
            return false;

        // only allow names starting '??--' if the ?? equals 'xn' (punycode); other such patterns
        // are reserved for other future DNS hacks (i.e. by DNS standards, not Session Router).
        if (primaryName.size() >= 4 and primaryName.substr(2, 2) == "--" and not primaryName.starts_with("xn"))
            return false;

        return true;
    }

}  // namespace srouter
