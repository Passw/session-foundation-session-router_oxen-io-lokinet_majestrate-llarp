#include "address.hpp"

#include "util/formattable.hpp"

#include <oxen/log.hpp>
#include <oxenc/base32z.h>

#include <stdexcept>

namespace srouter
{
    namespace log = oxen::log;
    static auto logcat = log::Cat("address");

    NetworkAddress::NetworkAddress(std::string_view arg)
    {
        bool was_pk_loki = false;
        if (arg.ends_with(RELAY_DOT_TLD))
        {
            is_client = false;
            arg.remove_suffix(RELAY_DOT_TLD.size());
        }
        else if (arg.ends_with(CLIENT_DOT_TLD))
        {
            is_client = true;
            arg.remove_suffix(CLIENT_DOT_TLD.size());
        }
        else if (arg.ends_with(".loki"))
        {
            is_client = true;
            arg.remove_suffix(5);
            was_pk_loki = true;
        }
        else
            throw std::invalid_argument{
                "Invalid network address '{}': expected *.{} or *.{}"_format(arg, CLIENT_TLD, RELAY_TLD)};

        if (!pubkey.from_base32z(arg))
            throw std::invalid_argument{"Invalid network address '{}.{}': expected full pubkey"_format(
                arg, is_client ? CLIENT_TLD : RELAY_TLD)};

        if (was_pk_loki)
            log::warning(
                logcat,
                "Address {0}…{1}.loki is deprecated: use {0}…{1}.{2} instead",
                arg.substr(0, 5),
                arg.substr(arg.size() - 3),
                CLIENT_TLD);
    }

    NetworkAddress::NetworkAddress(std::string_view arg, bool is_client) : is_client{is_client}
    {
        if (!pubkey.from_base32z(arg))
            throw std::invalid_argument{"Invalid NetworkAddress pubkey: {}"_format(arg)};
    }

    std::string NetworkAddress::to_string() const { return "{}.{}"_format(pubkey, is_client ? CLIENT_TLD : RELAY_TLD); }

}  //  namespace srouter
