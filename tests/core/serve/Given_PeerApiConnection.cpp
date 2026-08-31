#include <cstdint>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/serve/PeerApiConnection.h>

#include "fakes/types/nettype/FakeTcpSocket.h"

TEST(Given_PeerApiConnection, When_PeerDataArrives_Then_ItIsForwardedToLocalStream)
{
    auto peerState = std::make_shared<tailgate::tests::fakes::FakeTcpSocketState>();
    peerState->Incoming.push_back({1, 2, 3});
    auto localState = std::make_shared<tailgate::tests::fakes::FakeTcpSocketState>();
    tailgate::tests::fakes::FakeTcpSocket peer(peerState);
    tailgate::tests::fakes::FakeTcpSocket local(localState);
    tailgate::serve::PeerApiConnection connection(peer, local);

    const tailgate::serve::PeerApiConnectionStatus status = connection.ProcessPeerInput();
    const bool flushed = connection.FlushLocalOutput();

    EXPECT_EQ(status, tailgate::serve::PeerApiConnectionStatus::Ready);
    EXPECT_TRUE(flushed);
    EXPECT_EQ(localState->Written, (std::vector<std::uint8_t>{1, 2, 3}));
    EXPECT_FALSE(connection.LocalOutputPending());
}

TEST(Given_PeerApiConnection, When_LocalWriteWouldBlock_Then_DataRemainsQueuedUntilWritable)
{
    auto peerState = std::make_shared<tailgate::tests::fakes::FakeTcpSocketState>();
    peerState->Incoming.push_back({4, 5, 6});
    auto localState = std::make_shared<tailgate::tests::fakes::FakeTcpSocketState>();
    localState->WriteWouldBlock = true;
    tailgate::tests::fakes::FakeTcpSocket peer(peerState);
    tailgate::tests::fakes::FakeTcpSocket local(localState);
    tailgate::serve::PeerApiConnection connection(peer, local);

    const tailgate::serve::PeerApiConnectionStatus status = connection.ProcessPeerInput();
    const bool initiallyFlushed = connection.FlushLocalOutput();
    const bool initiallyPending = connection.LocalOutputPending();
    localState->WriteWouldBlock = false;
    const bool eventuallyFlushed = connection.FlushLocalOutput();

    EXPECT_EQ(status, tailgate::serve::PeerApiConnectionStatus::Ready);
    EXPECT_FALSE(initiallyFlushed);
    EXPECT_TRUE(initiallyPending);
    EXPECT_TRUE(eventuallyFlushed);
    EXPECT_EQ(localState->Written, (std::vector<std::uint8_t>{4, 5, 6}));
    EXPECT_FALSE(connection.LocalOutputPending());
}
