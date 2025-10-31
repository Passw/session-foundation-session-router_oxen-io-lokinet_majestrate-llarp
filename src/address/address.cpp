#include "address.hpp"

#include "util/formattable.hpp"

#include <oxenc/base32z.h>

#include <stdexcept>

namespace srouter
{
    NetworkAddress::NetworkAddress(std::string_view arg)
    {
        if (arg.ends_with(DOT_RELAY_TLD))
        {
            is_client = false;
            arg.remove_suffix(DOT_RELAY_TLD.size());
        }
        else if (arg.ends_with(DOT_CLIENT_TLD))
        {
            is_client = true;
            arg.remove_suffix(DOT_CLIENT_TLD.size());
        }
        else
            throw std::invalid_argument{
                "Invalid network address '{}': expected *.{} or *.{}"_format(arg, CLIENT_TLD, RELAY_TLD)};

        if (!pubkey.from_base32z(arg))
            throw std::invalid_argument{"Invalid network address '{}.{}': expected full pubkey"_format(
                arg, is_client ? CLIENT_TLD : RELAY_TLD)};
    }

    NetworkAddress::NetworkAddress(std::string_view arg, bool is_client) : is_client{is_client}
    {
        if (!pubkey.from_base32z(arg))
            throw std::invalid_argument{"Invalid NetworkAddress pubkey: {}"_format(arg)};
    }

    std::string NetworkAddress::to_string() const {
        return "{}.{}"_format(pubkey, is_client ? CLIENT_TLD : RELAY_TLD);
    }

}  //  namespace srouter
