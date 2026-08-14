#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/serve/PeerApiIngress.h>

namespace
{

class MemoryStream final : public tailgate::base::IByteStream
{
public:
    explicit MemoryStream(std::string input) : m_input(input.begin(), input.end())
    {
    }

    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                          std::size_t size) override
    {
        m_output.insert(m_output.end(), data, data + size);
        return size;
    }

    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maxBytes) override
    {
        if (m_offset >= m_input.size())
        {
            return std::vector<std::uint8_t>{};
        }
        const std::size_t count = std::min(maxBytes, m_input.size() - m_offset);
        std::vector<std::uint8_t> result(m_input.begin() + static_cast<std::ptrdiff_t>(m_offset),
                                         m_input.begin() +
                                             static_cast<std::ptrdiff_t>(m_offset + count));
        m_offset += count;
        return result;
    }

    [[nodiscard]] std::string Output() const
    {
        return {m_output.begin(), m_output.end()};
    }

private:
    std::vector<std::uint8_t> m_input;
    std::vector<std::uint8_t> m_output;
    std::size_t m_offset = 0;
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

TEST(Given_PeerApiIngress, When_TargetMatches_Then_UpgradeIsAccepted)
{
    tailgate::serve::PeerApiIngressHandler handler("node.example.ts.net:10000", "cert", "key");
    MemoryStream stream(IngressRequest("node.example.ts.net:10000"));

    const tailgate::serve::PeerApiIngressRequest request = handler.ReadRequestAndRespond(stream);

    EXPECT_EQ(tailgate::serve::PeerApiIngressStatus::Accepted, request.Status);
    EXPECT_EQ("203.0.113.4:12345", request.Source);
    EXPECT_EQ("node.example.ts.net:10000", request.Target);
    EXPECT_EQ("HTTP/1.1 101 Switching Protocols\r\n\r\n", stream.Output());
}

TEST(Given_PeerApiIngress, When_PathIsUnknown_Then_NotFoundIsReturned)
{
    tailgate::serve::PeerApiIngressHandler handler("node.example.ts.net:10000", "cert", "key");
    MemoryStream stream("GET / HTTP/1.1\r\nHost: peerapi\r\n\r\n");

    const tailgate::serve::PeerApiIngressRequest request = handler.ReadRequestAndRespond(stream);

    EXPECT_EQ(tailgate::serve::PeerApiIngressStatus::NotFound, request.Status);
    EXPECT_EQ("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", stream.Output());
}

TEST(Given_PeerApiIngress, When_TargetDiffers_Then_ForbiddenIsReturned)
{
    tailgate::serve::PeerApiIngressHandler handler("node.example.ts.net:10000", "cert", "key");
    MemoryStream stream(IngressRequest("other.example.ts.net:10000"));

    const tailgate::serve::PeerApiIngressRequest request = handler.ReadRequestAndRespond(stream);

    EXPECT_EQ(tailgate::serve::PeerApiIngressStatus::Forbidden, request.Status);
    EXPECT_EQ("203.0.113.4:12345", request.Source);
    EXPECT_EQ("other.example.ts.net:10000", request.Target);
    EXPECT_EQ("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", stream.Output());
}
