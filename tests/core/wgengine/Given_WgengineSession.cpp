#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/base/EventLoop.h>
#include <tailgate/derp/Connection.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/nettype/UdpSocket.h>
#include <tailgate/wgengine/Session.h>
#include <tailgate/wgengine/magicsock/Connection.h>

#include "fakes/derp/FakeConnection.h"
#include "fakes/di/FakeNetworkBindings.h"

namespace
{

using tailgate::tests::fakes::FakeEventLoop;
using tailgate::tests::fakes::FakeTimeProvider;
using tailgate::tests::fakes::FakeUdpSocketFactory;
using tailgate::tests::fakes::derp::FakeConnection;

constexpr tailgate::base::EventToken PlatformToken{.Value = 600};
constexpr tailgate::base::EventToken DerpToken{.Value = 601};
constexpr tailgate::base::EventToken MagicsockToken{.Value = 602};
constexpr std::size_t MaximumEvents = 8;
constexpr std::size_t MaximumPackets = 4;
constexpr std::size_t MaximumPacketSize = 4096;

TEST(Given_WgengineSession, When_PlatformEventIsUnhandled_Then_EventIsPreserved)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* eventLoop = &dynamic_cast<FakeEventLoop&>(injector.create<tailgate::base::EventLoop&>());
    tailgate::wgengine::Session& session = injector.create<tailgate::wgengine::Session&>();
    eventLoop->Next.Events.push_back(tailgate::base::Event{
        .Token = PlatformToken,
        .Readiness = tailgate::base::EventReadiness::Readable,
    });

    const tailgate::wgengine::SessionWaitResult result =
        session.Wait(MaximumEvents, MaximumPackets, MaximumPacketSize);

    EXPECT_EQ(eventLoop->TimedWaitCalls, 1U);
    EXPECT_EQ(result.PlatformEvents.size(), 1U);
    if (!result.PlatformEvents.empty())
    {
        EXPECT_EQ(result.PlatformEvents.front().Token, PlatformToken);
    }
    EXPECT_FALSE(result.MaintenanceDue);
}

TEST(Given_WgengineSession, When_MaintenanceDeadlineIsReached_Then_CoreMaintainsConnections)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* timeProvider =
        &dynamic_cast<FakeTimeProvider&>(injector.create<tailgate::base::TimeProvider&>());
    tailgate::wgengine::Session& session = injector.create<tailgate::wgengine::Session&>();
    auto connection =
        std::make_unique<FakeConnection>(DerpToken, tailgate::derp::DerpClient::Packet{});
    auto* connectionState = connection.get();
    const tailgate::wgengine::DerpConnectionId connectionId =
        session.AddDerpConnection(1, std::move(connection));
    timeProvider->Advance(std::chrono::seconds(1));

    const tailgate::wgengine::SessionWaitResult result =
        session.Wait(MaximumEvents, MaximumPackets, MaximumPacketSize);

    EXPECT_EQ(connectionId, 0U);
    EXPECT_TRUE(result.MaintenanceDue);
    EXPECT_EQ(connectionState->MaintenanceCalls, 1U);
    EXPECT_TRUE(result.PlatformEvents.empty());
}

TEST(Given_WgengineSession, When_DerpConnectionHandlesEvent_Then_PacketIsReturnedByConnection)
{
    tailgate::derp::DerpClient::Key source{};
    source.front() = 42;
    const std::vector<std::uint8_t> payload{1, 2, 3};
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* eventLoop = &dynamic_cast<FakeEventLoop&>(injector.create<tailgate::base::EventLoop&>());
    tailgate::wgengine::Session& session = injector.create<tailgate::wgengine::Session&>();
    const tailgate::wgengine::DerpConnectionId connection = session.AddDerpConnection(
        1,
        std::make_unique<FakeConnection>(
            DerpToken, tailgate::derp::DerpClient::Packet{.Source = source, .Payload = payload}));
    eventLoop->Next.Events.push_back(tailgate::base::Event{
        .Token = DerpToken,
        .Readiness = tailgate::base::EventReadiness::Readable,
    });

    const tailgate::wgengine::SessionWaitResult result =
        session.Wait(MaximumEvents, MaximumPackets, MaximumPacketSize);

    EXPECT_TRUE(result.PlatformEvents.empty());
    EXPECT_EQ(result.DerpPackets.size(), 1U);
    if (!result.DerpPackets.empty())
    {
        EXPECT_EQ(result.DerpPackets.front().Connection, connection);
        EXPECT_EQ(result.DerpPackets.front().Packet.Source, source);
        EXPECT_EQ(result.DerpPackets.front().Packet.Payload, payload);
    }
}

TEST(Given_WgengineSession, When_StunServerResponds_Then_PortableEndpointIsReturned)
{
    const tailgate::net::Endpoint server(tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 20),
                                         3478);
    const tailgate::net::Endpoint mapped(tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 10),
                                         41641);
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* eventLoop = &dynamic_cast<FakeEventLoop&>(injector.create<tailgate::base::EventLoop&>());
    auto* socketFactory = &dynamic_cast<FakeUdpSocketFactory&>(
        injector.create<tailgate::types::nettype::UdpSocketFactory&>());
    tailgate::wgengine::magicsock::Connection& magicsock =
        injector.create<tailgate::wgengine::magicsock::Connection&>();
    ASSERT_TRUE(magicsock.Open(tailgate::types::nettype::UdpSocketOptions{
        .BindEndpoint = {},
        .NetworkInterface = std::nullopt,
        .ReadinessToken = MagicsockToken,
    }));
    ASSERT_EQ(socketFactory->States.size(), 1U);
    auto* socketState = socketFactory->States.front().get();
    socketState->OnSend =
        [&](const tailgate::net::Endpoint&, const std::vector<std::uint8_t>& request)
    {
        std::vector<std::uint8_t> response{
            0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
            0x00, 0x08, 0x00, 0x01, 0x83, 0xbb, 0xe1, 0x12, 0xa6, 0x48,
        };
        std::copy_n(request.begin() + 8, 12, response.begin() + 8);
        socketState->Incoming.push_back(tailgate::types::nettype::UdpReceiveResult{
            .Result = tailgate::types::nettype::SocketIoResult::Complete,
            .Datagram =
                tailgate::types::nettype::UdpDatagram{
                    .Source = server,
                    .Payload = std::move(response),
                },
        });
        eventLoop->Next.Events.push_back(tailgate::base::Event{
            .Token = MagicsockToken,
            .Readiness = tailgate::base::EventReadiness::Readable,
        });
    };
    tailgate::wgengine::Session& session = injector.create<tailgate::wgengine::Session&>();

    const std::optional<tailgate::net::Endpoint> result =
        session.DiscoverEndpoint(server, std::chrono::seconds(3));

    EXPECT_EQ(result, mapped);
    EXPECT_EQ(eventLoop->TimedWaitCalls, 1U);
    EXPECT_EQ(socketState->Sent.size(), 1U);
    if (!socketState->Sent.empty())
    {
        EXPECT_EQ(socketState->Sent.front().Destination, server);
    }
}

TEST(Given_WgengineSession, When_PlaintextIsSent_Then_OwnedWireGuardRouterBuildsHandshake)
{
    tailgate::crypto::Bytes32 nodePrivateKey{};
    nodePrivateKey[1] = 1;
    tailgate::crypto::Bytes32 peerPrivateKey{};
    peerPrivateKey[1] = 2;
    const tailgate::crypto::Bytes32 peerPublicKey =
        tailgate::crypto::X25519PublicFromPrivate(peerPrivateKey);
    tailgate::types::netmap::PeerConfig peer;
    peer.Address("192.0.2.2");
    peer.Addresses({peer.Address()});
    peer.Key("nodekey:" + tailgate::crypto::BytesToHex(peerPublicKey.data(), peerPublicKey.size()));
    peer.AllowedPrefixes({tailgate::net::packet::Ipv4Prefix(
        tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 2).HostOrder(), 32)});
    const std::vector<std::uint8_t> plaintext = tailgate::net::packet::Ipv4Packet::Build(
        tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 1).HostOrder(),
        tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 2).HostOrder(),
        1,
        {1});
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    tailgate::wgengine::Session& session = injector.create<tailgate::wgengine::Session&>();
    auto derp = std::make_unique<FakeConnection>(DerpToken, tailgate::derp::DerpClient::Packet{});
    auto* derpState = derp.get();
    (void)session.AddDerpConnection(1, std::move(derp));
    session.Configure(tailgate::wgengine::SessionOptions{
        .NodePrivateKey = nodePrivateKey,
        .NodePublicKey = tailgate::crypto::X25519PublicFromPrivate(nodePrivateKey),
        .DiscoPrivateKey = {},
        .AdvertisedEndpoint =
            tailgate::net::Endpoint(tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 1), 41641),
        .HomeDerpRegion = 1,
        .Peers = {peer},
        .ExitNode = {},
    });

    session.SendPacket(plaintext);

    EXPECT_EQ(derpState->Sent.size(), 1U);
    if (!derpState->Sent.empty())
    {
        EXPECT_EQ(derpState->Sent.front().Destination, peerPublicKey);
        EXPECT_EQ(derpState->Sent.front().Priority,
                  tailgate::derp::DerpSendQueue::Priority::Control);
        EXPECT_FALSE(derpState->Sent.front().Payload.empty());
    }
}

TEST(Given_WgengineSession, When_DirectDiscoPingArrives_Then_CoreRepliesAndSelectsPath)
{
    tailgate::crypto::Bytes32 nodePrivateKey{};
    nodePrivateKey[1] = 3;
    const tailgate::crypto::Bytes32 nodePublicKey =
        tailgate::crypto::X25519PublicFromPrivate(nodePrivateKey);
    tailgate::crypto::Bytes32 discoPrivateKey{};
    discoPrivateKey[1] = 4;
    tailgate::disco::Disco localDisco(discoPrivateKey, nodePublicKey);
    tailgate::crypto::Bytes32 peerPrivateKey{};
    peerPrivateKey[1] = 5;
    const tailgate::crypto::Bytes32 peerPublicKey =
        tailgate::crypto::X25519PublicFromPrivate(peerPrivateKey);
    tailgate::crypto::Bytes32 peerDiscoPrivateKey{};
    peerDiscoPrivateKey[1] = 6;
    tailgate::disco::Disco peerDisco(peerDiscoPrivateKey, peerPublicKey);
    tailgate::types::netmap::PeerConfig peer;
    peer.Address("192.0.2.2");
    peer.Addresses({peer.Address()});
    peer.Key("nodekey:" + tailgate::crypto::BytesToHex(peerPublicKey.data(), peerPublicKey.size()));
    peer.DiscoKey("discokey:" + tailgate::crypto::BytesToHex(peerDisco.PublicKey().data(),
                                                             peerDisco.PublicKey().size()));
    peer.DerpRegion(1);
    const tailgate::net::Endpoint source(tailgate::net::Ipv4Address::FromOctets(198, 51, 100, 20),
                                         41641);
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* eventLoop = &dynamic_cast<FakeEventLoop&>(injector.create<tailgate::base::EventLoop&>());
    auto* socketFactory = &dynamic_cast<FakeUdpSocketFactory&>(
        injector.create<tailgate::types::nettype::UdpSocketFactory&>());
    tailgate::wgengine::magicsock::Connection& magicsock =
        injector.create<tailgate::wgengine::magicsock::Connection&>();
    ASSERT_TRUE(magicsock.Open(tailgate::types::nettype::UdpSocketOptions{
        .BindEndpoint = {},
        .NetworkInterface = std::nullopt,
        .ReadinessToken = MagicsockToken,
    }));
    ASSERT_EQ(socketFactory->States.size(), 1U);
    const tailgate::disco::Disco::TransactionId transaction = peerDisco.NewTransactionId();
    socketFactory->States.front()->Incoming.push_back(tailgate::types::nettype::UdpReceiveResult{
        .Result = tailgate::types::nettype::SocketIoResult::Complete,
        .Datagram =
            tailgate::types::nettype::UdpDatagram{
                .Source = source,
                .Payload = peerDisco.BuildPing(localDisco.PublicKey(), transaction),
            },
    });
    eventLoop->Next.Events.push_back(tailgate::base::Event{
        .Token = MagicsockToken,
        .Readiness = tailgate::base::EventReadiness::Readable,
    });
    tailgate::wgengine::Session& session = injector.create<tailgate::wgengine::Session&>();
    session.Configure(tailgate::wgengine::SessionOptions{
        .NodePrivateKey = nodePrivateKey,
        .NodePublicKey = nodePublicKey,
        .DiscoPrivateKey = discoPrivateKey,
        .AdvertisedEndpoint = {},
        .HomeDerpRegion = 1,
        .Peers = {peer},
        .ExitNode = {},
    });

    const tailgate::wgengine::SessionWaitResult result =
        session.Wait(MaximumEvents, MaximumPackets, MaximumPacketSize);

    EXPECT_EQ(result.DiscoEvents.size(), 1U);
    EXPECT_EQ(result.PathEvents.size(), 1U);
    EXPECT_EQ(magicsock.DirectEndpoint(peerPublicKey), source);
    EXPECT_EQ(socketFactory->States.front()->Sent.size(), 1U);
    if (!result.DiscoEvents.empty())
    {
        EXPECT_EQ(result.DiscoEvents.front().Peer, peerPublicKey);
        EXPECT_EQ(result.DiscoEvents.front().Type, tailgate::disco::Disco::MessageType::Ping);
        EXPECT_EQ(result.DiscoEvents.front().Transaction, transaction);
    }
    if (!socketFactory->States.front()->Sent.empty())
    {
        EXPECT_EQ(socketFactory->States.front()->Sent.front().Destination, source);
    }
}

TEST(Given_WgengineSession, When_DirectPathBecomesUnavailable_Then_DiscoPingRetriesVerifiedEndpoint)
{
    tailgate::crypto::Bytes32 nodePrivateKey{};
    nodePrivateKey[1] = 7;
    const tailgate::crypto::Bytes32 nodePublicKey =
        tailgate::crypto::X25519PublicFromPrivate(nodePrivateKey);
    tailgate::crypto::Bytes32 discoPrivateKey{};
    discoPrivateKey[1] = 8;
    tailgate::crypto::Bytes32 peerPrivateKey{};
    peerPrivateKey[1] = 9;
    const tailgate::crypto::Bytes32 peerPublicKey =
        tailgate::crypto::X25519PublicFromPrivate(peerPrivateKey);
    tailgate::crypto::Bytes32 peerDiscoPrivateKey{};
    peerDiscoPrivateKey[1] = 10;
    const tailgate::disco::Disco peerDisco(peerDiscoPrivateKey, peerPublicKey);
    tailgate::types::netmap::PeerConfig peer;
    peer.Address("192.0.2.2");
    peer.Addresses({peer.Address()});
    peer.Key("nodekey:" + tailgate::crypto::BytesToHex(peerPublicKey.data(), peerPublicKey.size()));
    peer.DiscoKey("discokey:" + tailgate::crypto::BytesToHex(peerDisco.PublicKey().data(),
                                                             peerDisco.PublicKey().size()));
    peer.DerpRegion(1);
    const tailgate::net::Endpoint verifiedEndpoint(
        tailgate::net::Ipv4Address::FromOctets(198, 51, 100, 30), 41641);
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* socketFactory = &dynamic_cast<FakeUdpSocketFactory&>(
        injector.create<tailgate::types::nettype::UdpSocketFactory&>());
    tailgate::wgengine::magicsock::Connection& magicsock =
        injector.create<tailgate::wgengine::magicsock::Connection&>();
    ASSERT_TRUE(magicsock.Open(tailgate::types::nettype::UdpSocketOptions{
        .BindEndpoint = {},
        .NetworkInterface = std::nullopt,
        .ReadinessToken = MagicsockToken,
    }));
    ASSERT_EQ(socketFactory->States.size(), 1U);
    tailgate::wgengine::Session& session = injector.create<tailgate::wgengine::Session&>();
    session.Configure(tailgate::wgengine::SessionOptions{
        .NodePrivateKey = nodePrivateKey,
        .NodePublicKey = nodePublicKey,
        .DiscoPrivateKey = discoPrivateKey,
        .AdvertisedEndpoint = {},
        .HomeDerpRegion = 1,
        .Peers = {peer},
        .ExitNode = {},
    });
    ASSERT_TRUE(magicsock.MarkDirect(peerPublicKey, verifiedEndpoint));
    magicsock.ResetPath(
        peerPublicKey,
        tailgate::wgengine::magicsock::PeerPathState::ResetMode::PreserveVerifiedEndpoints);

    const std::optional<tailgate::disco::Disco::TransactionId> transaction =
        session.SendDiscoPing(peerPublicKey);
    const auto& sent = socketFactory->States.front()->Sent;
    const std::optional<tailgate::net::Endpoint> destination =
        sent.empty() ? std::nullopt
                     : std::optional<tailgate::net::Endpoint>(sent.front().Destination);

    EXPECT_TRUE(transaction.has_value());
    EXPECT_EQ(sent.size(), 1U);
    EXPECT_EQ(destination, verifiedEndpoint);
}

} // namespace
