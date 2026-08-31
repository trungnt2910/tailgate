#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/serve/PeerApiIngress.h>

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
