#include <session/crypto/mlkem768.hpp>

#include <stdexcept>

// The mlkem-native builds from external/CMakeLists.txt, whose symbol prefixes (set there by
// MLK_CONFIG_NAMESPACE_PREFIX) these names must match.
extern "C"
{
    int mlkem768_baseline_keypair_derand(unsigned char* pk, unsigned char* sk, const unsigned char* coins);
    int mlkem768_baseline_enc_derand(
        unsigned char* ct, unsigned char* ss, const unsigned char* pk, const unsigned char* coins);
    int mlkem768_baseline_dec(unsigned char* ss, const unsigned char* ct, const unsigned char* sk);
#ifdef SROUTER_MLKEM768_AVX2_BUILD
    int mlkem768_avx2_keypair_derand(unsigned char* pk, unsigned char* sk, const unsigned char* coins);
    int mlkem768_avx2_enc_derand(
        unsigned char* ct, unsigned char* ss, const unsigned char* pk, const unsigned char* coins);
    int mlkem768_avx2_dec(unsigned char* ss, const unsigned char* ct, const unsigned char* sk);
#endif
}

namespace session::mlkem768
{
    namespace
    {
        unsigned char* uc(std::byte* p) { return reinterpret_cast<unsigned char*>(p); }
        const unsigned char* uc(const std::byte* p) { return reinterpret_cast<const unsigned char*>(p); }

        struct build
        {
            decltype(&mlkem768_baseline_keypair_derand) keypair_derand;
            decltype(&mlkem768_baseline_enc_derand) enc_derand;
            decltype(&mlkem768_baseline_dec) dec;
        };

        // Constant-initialized, so that a call from another static initializer that runs before the
        // selection below still finds a working (baseline) build rather than null pointers.
        constinit build impl{
            .keypair_derand = mlkem768_baseline_keypair_derand,
            .enc_derand = mlkem768_baseline_enc_derand,
            .dec = mlkem768_baseline_dec};

        // If we are already compiling for these then the baseline build includes the AVX2 code itself.
#if defined(SROUTER_MLKEM768_AVX2_BUILD) && !(defined(__AVX2__) && defined(__BMI2__) && defined(__POPCNT__))
        [[maybe_unused]] const bool selected = [] {
            // Needed when we run before the runtime's own constructor has filled in the CPU features.
            __builtin_cpu_init();
            // These also confirm that the OS preserves the AVX register state.
            if (__builtin_cpu_supports("avx2") && __builtin_cpu_supports("bmi2") && __builtin_cpu_supports("popcnt"))
                impl = {
                    .keypair_derand = mlkem768_avx2_keypair_derand,
                    .enc_derand = mlkem768_avx2_enc_derand,
                    .dec = mlkem768_avx2_dec};
            return true;
        }();
#endif
    }  // namespace

    void keygen(
        std::span<std::byte, PUBLICKEYBYTES> pk,
        std::span<std::byte, SECRETKEYBYTES> sk,
        std::span<const std::byte, SEEDBYTES> seed)
    {
        if (0 != impl.keypair_derand(uc(pk.data()), uc(sk.data()), uc(seed.data())))
            throw std::runtime_error{"ML-KEM-768 keygen failed"};
    }

    void encapsulate(
        std::span<std::byte, CIPHERTEXTBYTES> ciphertext,
        std::span<std::byte, SHAREDSECRETBYTES> shared_secret,
        std::span<const std::byte, PUBLICKEYBYTES> pk,
        std::span<const std::byte, SHAREDSECRETBYTES> seed)
    {
        if (0 != impl.enc_derand(uc(ciphertext.data()), uc(shared_secret.data()), uc(pk.data()), uc(seed.data())))
            throw std::runtime_error{"ML-KEM-768 encapsulation failed"};
    }

    bool decapsulate(
        std::span<std::byte, SHAREDSECRETBYTES> shared_secret,
        std::span<const std::byte, CIPHERTEXTBYTES> ciphertext,
        std::span<const std::byte, SECRETKEYBYTES> sk)
    {
        return 0 == impl.dec(uc(shared_secret.data()), uc(ciphertext.data()), uc(sk.data()));
    }

}  // namespace session::mlkem768
