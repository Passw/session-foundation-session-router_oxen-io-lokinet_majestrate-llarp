#pragma once

#include "common.hpp"
#include "contact/client_contact.hpp"
#include "contact/sns.hpp"

namespace srouter
{
    namespace PublishClientContact
    {
        extern const std::string INVALID;
        extern const std::string EXPIRED;

        std::vector<std::byte> serialize(const EncryptedClientContact& ecc, std::optional<int> location = std::nullopt);

        std::pair<EncryptedClientContact, std::optional<int>> deserialize(oxenc::bt_dict_consumer&& btdc);

    }  // namespace PublishClientContact

    namespace FindClientContact
    {
        /** Bt-encoded contents:
            - 'k' : blinded pubkey of the queried client contact
            - 'l' : lookup index, where 0 = closest, 3 = 4th closest.  -1 or omitted means "first to respond"

            Note: we are bt-encoding to leave space for future fields (ex: version)
         */
        std::vector<std::byte> serialize(const PubKey& location, int lookup_index);

        std::pair<PubKey, int> deserialize(oxenc::bt_dict_consumer&& btdc);

        /** Bt-encoded contents:
            - 'x' : EncryptedClientContact

            Note: we are bt-encoding to leave space for future fields (ex: version)
         */
        std::vector<std::byte> serialize_response(const EncryptedClientContact& ecc);

        EncryptedClientContact deserialize_response(oxenc::bt_dict_consumer&& btdc);

    }  //  namespace FindClientContact

}  // namespace srouter
