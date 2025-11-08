#pragma once

#include "client_intro.hpp"
#include "constants/version.hpp"
#include "crypto/crypto.hpp"
#include "dns/srv_data.hpp"
#include "net/policy.hpp"
#include "util/aligned.hpp"
#include "util/file.hpp"
#include "util/time.hpp"

#include <nlohmann/json_fwd.hpp>
#include <oxenc/bt_producer.h>

#include <unordered_set>
#include <vector>

namespace srouter
{
    inline static constexpr auto CC_PUBLISH_INTERVAL{5min};

    /** ClientContact
        On the wire we encode the data as a dict containing:
            - "" : the CC format version, which must be == ClientContact::VERSION to be parsed successfully
            - "a" : public key of the remote client instance
            - "e" : (optional) exit policy containing sublists of accepted protocols and routed IP ranges
            - "i" : list of client introductions corresponding to the different pivots through which paths can be built
                    to the client instance
            - "p" : supported protocols indicating the traffic accepted by the client instance; this indicates if the
                    client is embedded and therefore requires a tunneled connection. Serialized as a bitwise flag of
                    protocol_flag enums (llarp/net/policy.hpp)
            - "s" : (optional) SRV records for Session Router DNS lookup

        Note that we also store a signed_at value, but that is *not* carried inside the
        ClientContact but rather lives in the serialized encrypted wrapper; it is stored in the
        ClientContact via the outer wrapper value when decrypting (or when re-signing).
    */
    struct ClientContact
    {
        inline static constexpr uint8_t VERSION{0};

        ClientContact() = default;

        /// Constructs a ClientContact by parsing a serialized client contact value.  Throws if
        /// invalid.
        ClientContact(std::span<const std::byte> buf, sys_ms signed_at);

        /** Parameters:
            - `pk` : master identity key pubkey
            - `srvs` : SRV records (optional, can be empty)
            - `protocols` : client-supported protocols
            - `signed_at` : timestamp when the encrypted wrapper around this CC was signed
            - `policy` : exit-related traffic policy (optional)
         */
        ClientContact(
            PubKey pk,
            std::vector<dns::SRVData> srvs,
            protocol_flag protocols,
            sys_ms signed_at,
            std::optional<net::ExitPolicy> policy = std::nullopt);

        /// Decrypts a serialized, signed, encrypted ClientContact created by the (unblinded) pubkey
        /// `root` into a ClientContact.  Throws on failure.
        static ClientContact decrypt(std::span<const std::byte> buf, const PubKey& root);

        // TODO: there should be a limit on how large an encCC we will store on relays, and we should
        // check that when we generate & sign as well to make sure we don't exceed it.
        //
        // Encrypts and signs the client contact with the given blinded keypair.  Returns the
        // encrypted, signed, serialized value.
        std::string encrypt_and_sign(const Ed25519BlindedKey& blinded);

        /// Replaces the client intros in the current introset with the given values.  It is not
        /// necessary for the given values to be pre-sorted (i.e. this functions sorts them as
        /// required).
        void update_intros(std::vector<ClientIntro> intros);

        const PubKey& pubkey() const { return _pubkey; }
        // Returns the current intros; these will always be sorted in descending expiry order (i.e.
        // last entry is the first to expire).
        std::span<const ClientIntro> intros() const& { return _intros; }

        std::span<const dns::SRVData> SRVs() const { return _srv; }

        protocol_flag protocols() const { return _protos; }

        const std::optional<net::ExitPolicy>& exit_policy() const { return _exit_policy; }

        std::chrono::sys_seconds expiry() const;
        bool is_expired(sys_ms now = srouter::time_now_ms()) const;

        const sys_ms& signed_at() const { return _signed_at; }

      private:
        PubKey _pubkey{};

        std::vector<ClientIntro> _intros;
        std::vector<dns::SRVData> _srv;

        protocol_flag _protos{};

        sys_ms _signed_at{};

        // In exit mode, we advertise our policy for accepted traffic and the corresponding ranges
        std::optional<net::ExitPolicy> _exit_policy;

        std::vector<std::byte> bt_encode() const;

      public:
        bool operator==(const ClientContact& other) const
        {
            return std::tie(_pubkey, _intros, _srv, _protos, _exit_policy)
                == std::tie(other._pubkey, other._intros, other._srv, other._protos, other._exit_policy);
        }

        std::string to_string() const;
        static constexpr bool to_string_formattable = true;
    };

}  //  namespace srouter
