#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/net/tls/TlsStream.h>
#include <tailgate/serve/PeerApiIngress.h>

#include "fakes/crypto/TestCertificates.h"

namespace
{

class MemoryByteStream final : public tailgate::base::ByteStream
{
public:
    explicit MemoryByteStream(std::string input) : Input(input.begin(), input.end())
    {
    }

    std::optional<std::size_t> TryWriteSome(const std::uint8_t* data, std::size_t size) override
    {
        Output.insert(Output.end(), data, data + size);
        return size;
    }

    std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t maximumSize) override
    {
        const std::size_t count = std::min(maximumSize, Input.size() - Offset);
        std::vector<std::uint8_t> result(Input.begin() + static_cast<std::ptrdiff_t>(Offset),
                                         Input.begin() +
                                             static_cast<std::ptrdiff_t>(Offset + count));
        Offset += count;
        return result;
    }

    [[nodiscard]] std::string OutputString() const
    {
        return {Output.begin(), Output.end()};
    }

    std::vector<std::uint8_t> Input;
    std::vector<std::uint8_t> Output;
    std::size_t Offset = 0;
};

std::string IngressRequest(std::string target)
{
    return "POST /v0/ingress HTTP/1.1\r\n"
           "Host: peerapi\r\n"
           "Tailscale-Ingress-Src: 203.0.113.4:12345\r\n"
           "Tailscale-Ingress-Target: " +
           target +
           "\r\n"
           "\r\n";
}

} // namespace

namespace
{

class PairedByteStream final : public tailgate::base::ByteStream
{
public:
    PairedByteStream(std::deque<std::uint8_t>& input, std::deque<std::uint8_t>& output)
        : m_input(input), m_output(output)
    {
    }

    std::optional<std::size_t> TryWriteSome(const std::uint8_t* data, std::size_t size) override
    {
        m_output.insert(m_output.end(), data, data + size);
        return size;
    }

    std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t maximumSize) override
    {
        if (m_input.empty())
        {
            return std::nullopt;
        }
        const auto end =
            m_input.begin() + static_cast<std::ptrdiff_t>(std::min(maximumSize, m_input.size()));
        std::vector<std::uint8_t> result(m_input.begin(), end);
        m_input.erase(m_input.begin(), end);
        return result;
    }

private:
    std::deque<std::uint8_t>& m_input;
    std::deque<std::uint8_t>& m_output;
};

class Given_IngressTlsStream : public testing::Test
{
protected:
    void SetUp() override
    {
        // Deliver the TLS 1.2 handshake flights explicitly; no polling or real network is needed.
        m_server = m_handler.OpenTlsStream(m_serverTransport);
        ASSERT_FALSE(m_client.TryReadSome(1).has_value());
        ASSERT_FALSE(m_server->TryReadSome(1).has_value());
        ASSERT_FALSE(m_client.TryReadSome(1).has_value());
        ASSERT_TRUE(m_client.HandshakeComplete());
    }

    std::deque<std::uint8_t> m_toClient;
    std::deque<std::uint8_t> m_toServer;
    PairedByteStream m_clientTransport{m_toClient, m_toServer};
    PairedByteStream m_serverTransport{m_toServer, m_toClient};
    tailgate::serve::PeerApiIngressHandler m_handler{
        "node.example.ts.net:10000",
        std::string(tailgate::tests::fakes::IngressCertificate),
        std::string(tailgate::tests::fakes::IngressPrivateKey)};
    tailgate::net::tls::TlsStream m_client{
        m_clientTransport,
        "node.example.ts.net",
        std::vector<std::uint8_t>(tailgate::tests::fakes::IngressCertificate.begin(),
                                  tailgate::tests::fakes::IngressCertificate.end())};
    std::unique_ptr<tailgate::base::ByteStream> m_server;
};

} // namespace

TEST_F(Given_IngressTlsStream, When_ReadBudgetIsUnboundedAndIdle_Then_ReadWouldBlock)
{
    constexpr std::size_t MaximumBudget = std::numeric_limits<std::size_t>::max();

    const auto result = m_server->TryReadSome(MaximumBudget);

    EXPECT_FALSE(result.has_value());
}

TEST_F(Given_IngressTlsStream, When_ReadBudgetIsUnboundedAndDataExists_Then_OnlyDataIsReturned)
{
    const std::vector<std::uint8_t> payload{1, 2, 3, 4};
    ASSERT_EQ(m_client.TryWriteSome(payload.data(), payload.size()), payload.size());

    const auto result = m_server->TryReadSome(std::numeric_limits<std::size_t>::max());

    EXPECT_EQ(result, payload);
}

TEST_F(Given_IngressTlsStream, When_ReadBudgetShrinks_Then_ReadsRespectBudgetAndOwnTheirData)
{
    const std::vector<std::uint8_t> payload{1, 2, 3, 4};
    constexpr std::size_t LargeBudget = 16U * 1024U;
    ASSERT_FALSE(m_server->TryReadSome(LargeBudget).has_value());
    ASSERT_EQ(m_client.TryWriteSome(payload.data(), payload.size()), payload.size());

    const auto first = m_server->TryReadSome(1);
    const auto second = m_server->TryReadSome(3);
    const auto idle = m_server->TryReadSome(1);

    EXPECT_EQ(first, (std::vector<std::uint8_t>{1}));
    EXPECT_EQ(second, (std::vector<std::uint8_t>{2, 3, 4}));
    EXPECT_FALSE(idle.has_value());
}

TEST(Given_PeerApiIngress, When_TargetMatches_Then_UpgradeIsAccepted)
{
    tailgate::serve::PeerApiIngressHandler handler("node.example.ts.net:10000", "cert", "key");
    MemoryByteStream stream(IngressRequest("node.example.ts.net:10000"));

    const tailgate::serve::PeerApiIngressRequest request = handler.ReadRequestAndRespond(stream);

    EXPECT_EQ(tailgate::serve::PeerApiIngressStatus::Accepted, request.Status);
    EXPECT_EQ("203.0.113.4:12345", request.Source);
    EXPECT_EQ("node.example.ts.net:10000", request.Target);
    EXPECT_EQ("HTTP/1.1 101 Switching Protocols\r\n\r\n", stream.OutputString());
}

TEST(Given_PeerApiIngress, When_PathIsUnknown_Then_NotFoundIsReturned)
{
    tailgate::serve::PeerApiIngressHandler handler("node.example.ts.net:10000", "cert", "key");
    MemoryByteStream stream("GET / HTTP/1.1\r\nHost: peerapi\r\n\r\n");

    const tailgate::serve::PeerApiIngressRequest request = handler.ReadRequestAndRespond(stream);

    EXPECT_EQ(tailgate::serve::PeerApiIngressStatus::NotFound, request.Status);
    EXPECT_EQ("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", stream.OutputString());
}

TEST(Given_PeerApiIngress, When_TargetDiffers_Then_ForbiddenIsReturned)
{
    tailgate::serve::PeerApiIngressHandler handler("node.example.ts.net:10000", "cert", "key");
    MemoryByteStream stream(IngressRequest("other.example.ts.net:10000"));

    const tailgate::serve::PeerApiIngressRequest request = handler.ReadRequestAndRespond(stream);

    EXPECT_EQ(tailgate::serve::PeerApiIngressStatus::Forbidden, request.Status);
    EXPECT_EQ("203.0.113.4:12345", request.Source);
    EXPECT_EQ("other.example.ts.net:10000", request.Target);
    EXPECT_EQ("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", stream.OutputString());
}
