#include <chrono>
#include <string>

#include <gtest/gtest.h>

#include "crypto/impl/MbedTlsCertificate.h"

#include "fakes/crypto/TestCertificates.h"

namespace
{

constexpr auto MinimumValidity = std::chrono::hours(24);

} // namespace

TEST(Given_Certificate, When_CheckingCachedCertificate_Then_FreshCertificateIsAccepted)
{
    tailgate::crypto::impl::MbedTlsCertificate crypto;

    const bool valid = crypto.CertificateValidFor(
        std::string(tailgate::tests::fakes::ExampleCertificate), MinimumValidity);

    EXPECT_TRUE(valid);
}

TEST(Given_Certificate, When_HashingKnownInput_Then_ReturnsSha256Digest)
{
    tailgate::crypto::impl::MbedTlsCertificate crypto;

    const tailgate::crypto::Bytes32 digest = crypto.Sha256("abc");

    EXPECT_EQ(digest, (tailgate::crypto::Bytes32{0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                                                 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                                                 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                                                 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad}));
}
