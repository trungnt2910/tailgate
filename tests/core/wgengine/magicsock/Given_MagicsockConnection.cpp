#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/base/EventLoop.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/net/Endpoint.h>
#include <tailgate/types/nettype/UdpSocket.h>
#include <tailgate/wgengine/magicsock/Connection.h>

#include "fakes/base/FakeTimeProvider.h"
#include "fakes/di/FakeNetworkBindings.h"

namespace
{

namespace nettype = tailgate::types::nettype;
namespace magicsock = tailgate::wgengine::magicsock;
using tailgate::tests::fakes::FakeTimeProvider;
using tailgate::tests::fakes::FakeUdpSocketFactory;

constexpr tailgate::base::EventToken SocketToken{.Value = 100};
constexpr std::uint16_t DestinationPort = 41641;
constexpr std::size_t TestReceiveSize = 4096;

class Given_MagicsockConnection : public testing::Test
{
protected:
    Given_MagicsockConnection()
        : m_timeProvider(nullptr), m_socketFactory(nullptr), m_subject(nullptr)
    {
        tailgate::tests::fakes::InstallFakeNetworkBindings(m_injector);
        m_timeProvider =
            &dynamic_cast<FakeTimeProvider&>(m_injector.create<tailgate::base::TimeProvider&>());
        m_socketFactory = &dynamic_cast<FakeUdpSocketFactory&>(
            m_injector.create<tailgate::types::nettype::UdpSocketFactory&>());
        m_subject = &m_injector.create<magicsock::Connection&>();
    }

    static tailgate::crypto::Bytes32 Peer(std::uint8_t marker)
    {
        tailgate::crypto::Bytes32 peer{};
        peer.front() = marker;
        return peer;
    }

    static tailgate::net::Endpoint Destination()
    {
        return tailgate::net::Endpoint(tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 2),
                                       DestinationPort);
    }

    static nettype::UdpSocketOptions Options()
    {
        return nettype::UdpSocketOptions{
            .BindEndpoint = {},
            .NetworkInterface = "test-interface",
            .ReadinessToken = SocketToken,
        };
    }

    tailgate::di::Injector m_injector;
    FakeTimeProvider* m_timeProvider;
    FakeUdpSocketFactory* m_socketFactory;
    magicsock::Connection* m_subject;
};

TEST_F(Given_MagicsockConnection, When_Opened_Then_SocketUsesRequestedOptions)
{
    nettype::UdpSocketOptions options = Options();
    options.BindEndpoint =
        tailgate::net::Endpoint(tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 1), 12345);

    const bool opened = m_subject->Open(options);

    ASSERT_EQ(m_socketFactory->Options.size(), 1U);
    EXPECT_TRUE(opened);
    EXPECT_EQ(m_socketFactory->Options.front().BindEndpoint, options.BindEndpoint);
    EXPECT_EQ(m_socketFactory->Options.front().NetworkInterface, options.NetworkInterface);
    EXPECT_EQ(m_subject->LocalEndpoint(), options.BindEndpoint);
}

TEST_F(Given_MagicsockConnection, When_ProbeIsSent_Then_SocketCarriesDatagram)
{
    const std::vector<std::uint8_t> payload{1, 2, 3};
    const tailgate::net::Endpoint destination = Destination();
    ASSERT_TRUE(m_subject->Open(Options()));
    ASSERT_EQ(m_socketFactory->States.size(), 1U);

    const std::optional<nettype::SocketIoResult> result =
        m_subject->TrySendProbe(destination, payload);

    ASSERT_EQ(m_socketFactory->States.front()->Sent.size(), 1U);
    EXPECT_EQ(result, nettype::SocketIoResult::Complete);
    EXPECT_EQ(m_socketFactory->States.front()->Sent.front().Destination, destination);
    EXPECT_EQ(m_socketFactory->States.front()->Sent.front().Payload, payload);
}

TEST_F(Given_MagicsockConnection, When_ProbeIsSentToKnownPeerEndpoint_Then_PathIsNotPromoted)
{
    const tailgate::crypto::Bytes32 peer = Peer(1);
    const std::vector<std::uint8_t> payload{1, 2, 3};
    const tailgate::net::Endpoint destination = Destination();
    ASSERT_TRUE(m_subject->Open(Options()));
    ASSERT_TRUE(m_subject->AddPeer(peer));

    const std::optional<nettype::SocketIoResult> result =
        m_subject->TrySendProbe(destination, payload);

    EXPECT_EQ(result, nettype::SocketIoResult::Complete);
    EXPECT_FALSE(m_subject->HasDirectPath(peer));
    EXPECT_FALSE(m_subject->DirectEndpoint(peer).has_value());
}

TEST_F(Given_MagicsockConnection, When_DirectPacketIsSent_Then_TheSharedSocketCarriesDatagram)
{
    const tailgate::crypto::Bytes32 peer = Peer(1);
    const std::vector<std::uint8_t> payload{4, 5, 6};
    const tailgate::net::Endpoint destination = Destination();
    ASSERT_TRUE(m_subject->Open(Options()));
    ASSERT_TRUE(m_subject->AddPeer(peer));
    ASSERT_EQ(m_socketFactory->States.size(), 1U);

    const std::optional<nettype::SocketIoResult> result =
        m_subject->TrySendDirect(peer, destination, payload);

    ASSERT_EQ(m_socketFactory->States.front()->Sent.size(), 1U);
    EXPECT_EQ(result, nettype::SocketIoResult::Complete);
    EXPECT_EQ(m_socketFactory->States.front()->Sent.front().Destination, destination);
    EXPECT_EQ(m_socketFactory->States.front()->Sent.front().Payload, payload);
}

TEST_F(Given_MagicsockConnection, When_ExplicitEndpointPacketIsSent_Then_PathIsNotPromoted)
{
    const tailgate::crypto::Bytes32 peer = Peer(1);
    const std::vector<std::uint8_t> payload{4, 5, 6};
    const tailgate::net::Endpoint destination = Destination();
    ASSERT_TRUE(m_subject->Open(Options()));
    ASSERT_TRUE(m_subject->AddPeer(peer));

    const magicsock::Connection::DirectSendResult result =
        m_subject->SendDirect(peer, destination, payload);

    EXPECT_EQ(result, magicsock::Connection::DirectSendResult::Sent);
    EXPECT_FALSE(m_subject->HasDirectPath(peer));
    EXPECT_FALSE(m_subject->DirectEndpoint(peer).has_value());
}

TEST_F(Given_MagicsockConnection, When_PeerHasNoSelectedPath_Then_PathSelectedSendIsUnavailable)
{
    const tailgate::crypto::Bytes32 peer = Peer(8);
    ASSERT_TRUE(m_subject->Open(Options()));
    ASSERT_TRUE(m_subject->AddPeer(peer));

    const magicsock::Connection::DirectSendResult result = m_subject->Send(peer, {1});

    EXPECT_EQ(result, magicsock::Connection::DirectSendResult::Unavailable);
    EXPECT_TRUE(m_socketFactory->States.front()->Sent.empty());
}

TEST_F(Given_MagicsockConnection, When_PeerPathIsSelected_Then_SendUsesSelectedEndpoint)
{
    const tailgate::crypto::Bytes32 peer = Peer(9);
    const tailgate::net::Endpoint destination = Destination();
    const std::vector<std::uint8_t> payload{2, 3};
    ASSERT_TRUE(m_subject->Open(Options()));
    ASSERT_TRUE(m_subject->AddPeer(peer));
    ASSERT_TRUE(m_subject->MarkDirect(peer, destination));

    const magicsock::Connection::DirectSendResult result = m_subject->Send(peer, payload);

    EXPECT_EQ(result, magicsock::Connection::DirectSendResult::Sent);
    EXPECT_TRUE(m_subject->HasDirectPath(peer));
    EXPECT_EQ(m_subject->DirectEndpoint(peer), destination);
    EXPECT_EQ(m_socketFactory->States.front()->Sent.size(), 1U);
    if (!m_socketFactory->States.front()->Sent.empty())
    {
        EXPECT_EQ(m_socketFactory->States.front()->Sent.front().Destination, destination);
        EXPECT_EQ(m_socketFactory->States.front()->Sent.front().Payload, payload);
    }
}

TEST_F(Given_MagicsockConnection, When_VerifiedDirectSourceReplies_Then_SelectedPathRemainsLive)
{
    const tailgate::crypto::Bytes32 peer = Peer(10);
    const tailgate::net::Endpoint destination = Destination();
    ASSERT_TRUE(m_subject->Open(Options()));
    ASSERT_TRUE(m_subject->AddPeer(peer));
    ASSERT_TRUE(m_subject->MarkDirect(peer, destination));
    ASSERT_EQ(m_subject->Send(peer, {1}), magicsock::Connection::DirectSendResult::Sent);

    const std::optional<tailgate::crypto::Bytes32> accepted =
        m_subject->AcceptDirectSource(destination);
    m_timeProvider->Advance(magicsock::PeerPathState::DirectPathTimeout + std::chrono::seconds(1));
    const bool expired = m_subject->ExpireDirectPath(peer);

    EXPECT_EQ(accepted, peer);
    EXPECT_FALSE(expired);
    EXPECT_TRUE(m_subject->HasDirectPath(peer));
}

TEST_F(Given_MagicsockConnection, When_UnknownPeerIsUsed_Then_DirectSendIsUnavailable)
{
    ASSERT_TRUE(m_subject->Open(Options()));

    const std::optional<nettype::SocketIoResult> result =
        m_subject->TrySendDirect(Peer(2), Destination(), {7});

    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(m_socketFactory->States.front()->Sent.empty());
}

TEST_F(Given_MagicsockConnection, When_PeerIsRemoved_Then_DirectSendIsRejected)
{
    const tailgate::crypto::Bytes32 peer = Peer(3);
    ASSERT_TRUE(m_subject->Open(Options()));
    ASSERT_TRUE(m_subject->AddPeer(peer));

    const bool removed = m_subject->RemovePeer(peer);
    const std::optional<nettype::SocketIoResult> result =
        m_subject->TrySendDirect(peer, Destination(), {8});

    EXPECT_TRUE(removed);
    EXPECT_FALSE(m_subject->HasPeer(peer));
    EXPECT_FALSE(result.has_value());
    EXPECT_FALSE(m_socketFactory->States.front()->Closed);
}

TEST_F(Given_MagicsockConnection, When_PeerIsAddedTwice_Then_NoAdditionalSocketIsCreated)
{
    const tailgate::crypto::Bytes32 peer = Peer(4);
    ASSERT_TRUE(m_subject->Open(Options()));
    ASSERT_TRUE(m_subject->AddPeer(peer));

    const bool addedAgain = m_subject->AddPeer(peer);

    EXPECT_FALSE(addedAgain);
    EXPECT_EQ(m_socketFactory->States.size(), 1U);
}

TEST_F(Given_MagicsockConnection, When_DirectSendWouldBlock_Then_DatagramIsQueued)
{
    const tailgate::crypto::Bytes32 peer = Peer(5);
    const std::vector<std::uint8_t> payload{9, 10};
    ASSERT_TRUE(m_subject->Open(Options()));
    ASSERT_TRUE(m_subject->AddPeer(peer));
    ASSERT_EQ(m_socketFactory->States.size(), 1U);
    m_socketFactory->States.front()->SendResult = nettype::SocketIoResult::WouldBlock;

    const magicsock::Connection::DirectSendResult result =
        m_subject->SendDirect(peer, Destination(), payload);

    EXPECT_EQ(result, magicsock::Connection::DirectSendResult::Queued);
    EXPECT_EQ(m_subject->QueuedPackets(peer), 1U);
    EXPECT_EQ(m_subject->QueuedBytes(peer), payload.size());
    EXPECT_TRUE(m_socketFactory->States.front()->WriteInterest);
}

TEST_F(Given_MagicsockConnection, When_DirectPathIsUnavailable_Then_DatagramIsNotQueued)
{
    const tailgate::crypto::Bytes32 peer = Peer(11);
    ASSERT_TRUE(m_subject->Open(Options()));
    ASSERT_TRUE(m_subject->AddPeer(peer));
    ASSERT_EQ(m_socketFactory->States.size(), 1U);
    m_socketFactory->States.front()->SendResult = nettype::SocketIoResult::Unavailable;

    const magicsock::Connection::DirectSendResult result =
        m_subject->SendDirect(peer, Destination(), {1, 2});

    EXPECT_EQ(result, magicsock::Connection::DirectSendResult::Unavailable);
    EXPECT_EQ(m_subject->QueuedPackets(peer), 0U);
    EXPECT_FALSE(m_socketFactory->States.front()->WriteInterest);
}

TEST_F(Given_MagicsockConnection, When_SocketBecomesWritable_Then_QueuedDatagramIsFlushed)
{
    const tailgate::crypto::Bytes32 peer = Peer(6);
    const std::vector<std::uint8_t> payload{11, 12};
    ASSERT_TRUE(m_subject->Open(Options()));
    ASSERT_TRUE(m_subject->AddPeer(peer));
    ASSERT_EQ(m_socketFactory->States.size(), 1U);
    m_socketFactory->States.front()->SendResult = nettype::SocketIoResult::WouldBlock;
    ASSERT_EQ(m_subject->SendDirect(peer, Destination(), payload),
              magicsock::Connection::DirectSendResult::Queued);
    m_socketFactory->States.front()->SendResult = nettype::SocketIoResult::Complete;
    const tailgate::base::Event event{
        .Token = SocketToken,
        .Readiness = tailgate::base::EventReadiness::Writable,
    };

    const magicsock::Connection::EventResult result =
        m_subject->ProcessEvent(event, 1, TestReceiveSize);

    ASSERT_EQ(m_socketFactory->States.front()->Sent.size(), 1U);
    EXPECT_TRUE(result.Handled);
    EXPECT_EQ(result.Status, magicsock::Connection::EventStatus::Ready);
    EXPECT_EQ(m_socketFactory->States.front()->Sent.front().Payload, payload);
    EXPECT_EQ(m_subject->QueuedPackets(peer), 0U);
    EXPECT_FALSE(m_socketFactory->States.front()->WriteInterest);
}

TEST_F(Given_MagicsockConnection, When_SocketIsReadable_Then_DatagramIsReturned)
{
    const nettype::UdpDatagram datagram{.Source = Destination(), .Payload = {13, 14}};
    ASSERT_TRUE(m_subject->Open(Options()));
    ASSERT_EQ(m_socketFactory->States.size(), 1U);
    m_socketFactory->States.front()->Incoming.push_back(nettype::UdpReceiveResult{
        .Result = nettype::SocketIoResult::Complete,
        .Datagram = datagram,
    });
    const tailgate::base::Event event{
        .Token = SocketToken,
        .Readiness = tailgate::base::EventReadiness::Readable,
    };

    const magicsock::Connection::EventResult result =
        m_subject->ProcessEvent(event, 1, TestReceiveSize);

    ASSERT_EQ(result.Datagrams.size(), 1U);
    EXPECT_TRUE(result.Handled);
    EXPECT_EQ(result.Datagrams.front().Source, datagram.Source);
    EXPECT_EQ(result.Datagrams.front().Payload, datagram.Payload);
}

TEST_F(Given_MagicsockConnection, When_UnrelatedEventArrives_Then_ItIsNotHandled)
{
    ASSERT_TRUE(m_subject->Open(Options()));
    const tailgate::base::Event event{
        .Token = tailgate::base::EventToken{.Value = SocketToken.Value + 1},
        .Readiness = tailgate::base::EventReadiness::Readable,
    };

    const magicsock::Connection::EventResult result =
        m_subject->ProcessEvent(event, 1, TestReceiveSize);

    EXPECT_FALSE(result.Handled);
    EXPECT_TRUE(result.Datagrams.empty());
}

TEST_F(Given_MagicsockConnection, When_SocketCloses_Then_TypedStatusIsReturned)
{
    ASSERT_TRUE(m_subject->Open(Options()));
    const tailgate::base::Event event{
        .Token = SocketToken,
        .Readiness = tailgate::base::EventReadiness::Closed,
    };

    const magicsock::Connection::EventResult result =
        m_subject->ProcessEvent(event, 1, TestReceiveSize);

    EXPECT_TRUE(result.Handled);
    EXPECT_EQ(result.Status, magicsock::Connection::EventStatus::Closed);
}

TEST_F(Given_MagicsockConnection, When_ConnectionCloses_Then_TheOwnedSocketAndPeerStateClose)
{
    const tailgate::crypto::Bytes32 peer = Peer(7);
    ASSERT_TRUE(m_subject->Open(Options()));
    ASSERT_TRUE(m_subject->AddPeer(peer));
    ASSERT_EQ(m_socketFactory->States.size(), 1U);

    m_subject->Close();

    EXPECT_TRUE(m_socketFactory->States.front()->Closed);
    EXPECT_FALSE(m_subject->HasPeer(peer));
    EXPECT_FALSE(m_subject->LocalEndpoint().has_value());
}

} // namespace
