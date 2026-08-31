#include <gtest/gtest.h>

#include "support/BufferedByteStream.h"

#include "PeerApiServer.h"

TEST(Given_PeerApiServer, When_NoTlsInputIsBuffered_Then_EventLoopWaitsForFd)
{
    tailgate::tests::support::BufferedByteStream stream(false);

    const int timeout = tailgate::linux_frontend::PeerApiWaitTimeout(stream);

    EXPECT_EQ(-1, timeout);
}

TEST(Given_PeerApiServer, When_TlsInputIsBuffered_Then_EventLoopDoesNotBlock)
{
    tailgate::tests::support::BufferedByteStream stream(true);

    const int timeout = tailgate::linux_frontend::PeerApiWaitTimeout(stream);

    EXPECT_EQ(0, timeout);
}

TEST(Given_PeerApiServer, When_TlsReadNeedsWrite_Then_EventLoopWaitsForFd)
{
    tailgate::tests::support::BufferedByteStream stream(true, true);

    const int timeout = tailgate::linux_frontend::PeerApiWaitTimeout(stream);

    EXPECT_EQ(-1, timeout);
}
