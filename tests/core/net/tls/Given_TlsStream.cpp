#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/net/tls/TlsStream.h>

#include "fakes/base/FakeByteStream.h"
#include "fakes/crypto/TestCertificates.h"

#include "TlsWriteProgress.h"

TEST(Given_TlsStream, When_HandshakeReachesEof_Then_ConstructionFailsAndReleasesResources)
{
    tailgate::tests::fakes::FakeByteStream transport("TLS transport");
    const std::string certificate(tailgate::tests::fakes::ExampleCertificate);
    const std::vector<std::uint8_t> caPem(certificate.begin(), certificate.end());
    bool rejected = false;

    try
    {
        tailgate::net::tls::TlsStream stream(transport, "node.example.ts.net", caPem, false);
    }
    catch (const std::runtime_error&)
    {
        rejected = true;
    }

    EXPECT_TRUE(rejected);
    EXPECT_EQ(transport.ReadCalls, 1U);
}

TEST(Given_TlsStream, When_CaIsEmpty_Then_ConstructionFailsBeforeUsingTransport)
{
    tailgate::tests::fakes::FakeByteStream transport("TLS transport");
    const std::vector<std::uint8_t> caPem;
    bool rejected = false;

    try
    {
        tailgate::net::tls::TlsStream stream(transport, "node.example.ts.net", caPem, false);
    }
    catch (const std::runtime_error&)
    {
        rejected = true;
    }

    EXPECT_TRUE(rejected);
    EXPECT_EQ(transport.ReadCalls, 0U);
    EXPECT_EQ(transport.WriteCalls, 0U);
}

TEST(Given_TlsStream, When_HandshakeReadWouldBlock_Then_ConstructionDoesNotPoll)
{
    tailgate::tests::fakes::FakeByteStream transport("TLS transport");
    transport.ReadWouldBlock = true;
    const std::string certificate(tailgate::tests::fakes::ExampleCertificate);
    const std::vector<std::uint8_t> caPem(certificate.begin(), certificate.end());

    tailgate::net::tls::TlsStream stream(transport, "node.example.ts.net", caPem, false);

    EXPECT_FALSE(stream.HandshakeComplete());
    EXPECT_TRUE(stream.WriteNeedsRead());
    EXPECT_FALSE(stream.ReadNeedsWrite());
    EXPECT_EQ(transport.ReadCalls, 1U);
}

TEST(Given_TlsStream, When_PendingHandshakeIsAdvanced_Then_OnlyOneReadAttemptOccursPerCall)
{
    tailgate::tests::fakes::FakeByteStream transport("TLS transport");
    transport.ReadWouldBlock = true;
    const std::string certificate(tailgate::tests::fakes::ExampleCertificate);
    const std::vector<std::uint8_t> caPem(certificate.begin(), certificate.end());
    tailgate::net::tls::TlsStream stream(transport, "node.example.ts.net", caPem, false);
    const std::size_t readsBeforeAdvance = transport.ReadCalls;

    const std::optional<std::vector<std::uint8_t>> result = stream.TryReadSome(1024);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(transport.ReadCalls, readsBeforeAdvance + 1U);
}

TEST(Given_TlsStream, When_WriteTransportWouldBlock_Then_WriteRemainsPending)
{
    constexpr int WantRead = -1;
    std::uint64_t readGeneration = 0;
    int calls = 0;

    const int result = tailgate::net::tls::detail::WriteWithReadProgress(
        [&]()
        {
            ++calls;
            return WantRead;
        },
        WantRead,
        readGeneration);

    EXPECT_EQ(result, WantRead);
    EXPECT_EQ(calls, 2);
    EXPECT_EQ(readGeneration, 0U);
}

TEST(Given_TlsStream, When_WriteInputProgresses_Then_WriteCompletes)
{
    constexpr int WantRead = -1;
    constexpr int Written = 42;
    std::uint64_t readGeneration = 0;
    int calls = 0;

    const int result = tailgate::net::tls::detail::WriteWithReadProgress(
        [&]()
        {
            ++calls;
            if (calls == 2)
            {
                ++readGeneration;
            }
            return calls < 3 ? WantRead : Written;
        },
        WantRead,
        readGeneration);

    EXPECT_EQ(result, Written);
    EXPECT_EQ(calls, 3);
    EXPECT_EQ(readGeneration, 1U);
}
