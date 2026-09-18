#include <array>
#include <barrier>
#include <cstddef>
#include <cstdint>
#include <thread>

#include <gtest/gtest.h>
#include <psa/crypto.h>

#include "crypto/PsaCryptoContext.h"

TEST(Given_PsaCryptoContext, When_ThreadsImportIndependentKeys_Then_AllKeysRetainTheirOwnData)
{
    constexpr std::size_t WorkerCount = 4;
    constexpr std::size_t Iterations = 64;
    constexpr std::size_t KeyBytes = 16;
    std::barrier start(static_cast<std::ptrdiff_t>(WorkerCount));
    std::array<std::size_t, WorkerCount> successful{};
    std::array<std::jthread, WorkerCount> workers;

    for (std::size_t worker = 0; worker < WorkerCount; ++worker)
    {
        workers[worker] = std::jthread(
            [&, worker]()
            {
                tailgate::crypto::detail::PsaCryptoContext context;
                std::array<std::uint8_t, KeyBytes> input{};
                input.fill(static_cast<std::uint8_t>(worker + 1));
                psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
                psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
                psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
                psa_set_key_bits(&attributes, KeyBytes * 8);
                start.arrive_and_wait();
                for (std::size_t iteration = 0; iteration < Iterations; ++iteration)
                {
                    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
                    const auto imported =
                        psa_import_key(&attributes, input.data(), input.size(), &key);
                    std::array<std::uint8_t, KeyBytes> output{};
                    std::size_t size = 0;
                    const auto exported = psa_export_key(key, output.data(), output.size(), &size);
                    const auto destroyed = psa_destroy_key(key);
                    successful[worker] += imported == PSA_SUCCESS && exported == PSA_SUCCESS &&
                                          destroyed == PSA_SUCCESS && size == input.size() &&
                                          output == input;
                }
                psa_reset_key_attributes(&attributes);
            });
    }
    for (auto& worker : workers)
    {
        worker.join();
    }

    EXPECT_EQ(
        successful,
        (std::array<std::size_t, WorkerCount>{Iterations, Iterations, Iterations, Iterations}));
}

TEST(Given_PsaCryptoContext, When_LastContextIsRecreated_Then_CryptoCanBeInitializedAgain)
{
    constexpr std::size_t Cycles = 3;
    std::array<psa_status_t, Cycles> results{};

    for (std::size_t cycle = 0; cycle < Cycles; ++cycle)
    {
        tailgate::crypto::detail::PsaCryptoContext context;
        std::array<std::uint8_t, 16> bytes{};
        results[cycle] = psa_generate_random(bytes.data(), bytes.size());
    }

    EXPECT_EQ(results, (std::array<psa_status_t, Cycles>{PSA_SUCCESS, PSA_SUCCESS, PSA_SUCCESS}));
}

TEST(Given_PsaCryptoContext, When_ThreadsSignWithIndependentEccKeys_Then_AllSignaturesVerify)
{
    constexpr std::size_t WorkerCount = 2;
    constexpr std::size_t Iterations = 8;
    constexpr std::size_t KeyBits = 256;
    constexpr std::size_t DigestBytes = 32;
    constexpr std::size_t SignatureBytes = 64;
    std::barrier start(static_cast<std::ptrdiff_t>(WorkerCount));
    std::array<std::size_t, WorkerCount> successful{};
    std::array<std::jthread, WorkerCount> workers;

    for (std::size_t worker = 0; worker < WorkerCount; ++worker)
    {
        workers[worker] = std::jthread(
            [&, worker]()
            {
                tailgate::crypto::detail::PsaCryptoContext context;
                std::array<std::uint8_t, DigestBytes> digest{};
                digest.fill(static_cast<std::uint8_t>(worker + 1));
                psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
                psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
                psa_set_key_usage_flags(&attributes,
                                        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
                psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
                psa_set_key_bits(&attributes, KeyBits);
                start.arrive_and_wait();
                for (std::size_t iteration = 0; iteration < Iterations; ++iteration)
                {
                    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
                    const auto generated = psa_generate_key(&attributes, &key);
                    std::array<std::uint8_t, SignatureBytes> signature{};
                    std::size_t size = 0;
                    const auto signedHash = psa_sign_hash(key,
                                                          PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                                          digest.data(),
                                                          digest.size(),
                                                          signature.data(),
                                                          signature.size(),
                                                          &size);
                    const auto verified = psa_verify_hash(key,
                                                          PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                                          digest.data(),
                                                          digest.size(),
                                                          signature.data(),
                                                          size);
                    const auto destroyed = psa_destroy_key(key);
                    successful[worker] += generated == PSA_SUCCESS && signedHash == PSA_SUCCESS &&
                                          verified == PSA_SUCCESS && destroyed == PSA_SUCCESS &&
                                          size == signature.size();
                }
                psa_reset_key_attributes(&attributes);
            });
    }
    for (auto& worker : workers)
    {
        worker.join();
    }

    EXPECT_EQ(successful, (std::array<std::size_t, WorkerCount>{Iterations, Iterations}));
}
