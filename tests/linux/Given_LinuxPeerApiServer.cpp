#include "LinuxPeerApiServer.h"

#include <gtest/gtest.h>

#include <optional>
#include <vector>

namespace
{

class BufferedStream final : public tailgate::IByteStream
{
public:
    explicit BufferedStream(bool buffered) : m_buffered(buffered)
    {
    }

    std::optional<std::size_t> TryWriteSome(const std::uint8_t*, std::size_t size) override
    {
        return size;
    }

    std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t) override
    {
        return std::nullopt;
    }

    bool HasBufferedInput() const override
    {
        return m_buffered;
    }

private:
    bool m_buffered = false;
};

} // namespace

TEST(Given_BufferedPeerApiTlsInput, When_SelectingWait_Then_EventLoopDoesNotBlock)
{
    BufferedStream stream(true);

    const int timeout = tailgate::linux_frontend::PeerApiWaitTimeout(stream);

    EXPECT_EQ(0, timeout);
}

TEST(Given_NoBufferedPeerApiTlsInput, When_SelectingWait_Then_EventLoopWaitsForFd)
{
    BufferedStream stream(false);

    const int timeout = tailgate::linux_frontend::PeerApiWaitTimeout(stream);

    EXPECT_EQ(-1, timeout);
}
