#include <memory>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/di/Bindings.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/wgengine/PeerProtocol.h>
#include <tailgate/wgengine/Session.h>
#include <tailgate/wgengine/wireguard/Tunnel.h>

#include "fakes/derp/FakeConnection.h"
#include "fakes/di/FakeNetworkBindings.h"

namespace tailgate::tests
{
namespace
{

constexpr base::EventToken DerpToken{.Value = 601};
constexpr std::size_t MaximumEvents = 8;
constexpr std::size_t MaximumPackets = 4;
constexpr std::size_t MaximumPacketSize = 4096;

class Given_PeerProtocol : public testing::Test
{
protected:
    void SetUp() override
    {
        fakes::InstallFakeNetworkBindings(m_injector);
        m_config.NodePrivateKey = crypto::GeneratePrivateKey();
        m_config.NodePublicKey = crypto::X25519PublicFromPrivate(m_config.NodePrivateKey);
        m_config.DiscoPrivateKey = crypto::GeneratePrivateKey();
        m_config.Network.SelfAddress("192.0.2.1");
        m_peerPrivate = crypto::GeneratePrivateKey();
        m_peerPublic = crypto::X25519PublicFromPrivate(m_peerPrivate);
        types::netmap::PeerConfig peer;
        peer.Key("nodekey:" + crypto::BytesToHex(m_peerPublic.data(), m_peerPublic.size()));
        peer.Address("192.0.2.2");
        peer.Addresses({peer.Address()});
        peer.DerpRegion(1);
        m_config.Network.Peers({peer});
        m_peer = std::make_unique<wgengine::wireguard::WireGuardTunnel>(m_peerPrivate);
        m_peerId = m_peer->AddPeer(m_config.NodePublicKey);
        auto& client = m_injector.create<hosted::Client&>();
        (void)client.Start(m_config);
        const auto response = client.Process(ServerPacket(m_peer->CreateHandshake(m_peerId)));
        hosted::Decoder decoder;
        decoder.Feed(response.RemoteOutput);
        const auto frame = decoder.Next();
        ASSERT_TRUE(frame.has_value());
        ASSERT_EQ(frame->Type(), hosted::MessageType::ClientPacket);
        const auto packet = hosted::ProtocolCodec::DecodePeerPacket(frame->Payload());
        ASSERT_TRUE(m_peer->ProcessPacket(m_peerId, packet.Payload()).has_value());
        ASSERT_TRUE(m_peer->HasSession(m_peerId));
        (void)client.Process(ServerPacket(m_peer->Encrypt(m_peerId, {})));
    }

    void ConfigureNative()
    {
        wgengine::SessionOptions options;
        options.NodePrivateKey = m_config.NodePrivateKey;
        options.NodePublicKey = m_config.NodePublicKey;
        options.DiscoPrivateKey = m_config.DiscoPrivateKey;
        options.HomeDerpRegion = 1;
        options.Peers = m_config.Network.Peers();
        m_injector.create<wgengine::Session&>().Configure(std::move(options));
    }

    hosted::Frame ServerPacket(const std::vector<std::uint8_t>& bytes)
    {
        return hosted::Frame(
            hosted::MessageType::ServerPacket,
            hosted::ProtocolCodec::EncodePeerPacket(hosted::PeerPacket(m_peerPublic, bytes)));
    }

    std::vector<std::uint8_t> Plaintext(bool fromPeer)
    {
        const auto local = net::Ipv4Address::FromOctets(192, 0, 2, 1).HostOrder();
        const auto remote = net::Ipv4Address::FromOctets(192, 0, 2, 2).HostOrder();
        return net::packet::Ipv4Packet::Build(
            fromPeer ? remote : local, fromPeer ? local : remote, 17, {1, 2, 3, 4});
    }

    di::Injector m_injector;
    hosted::ClientConfig m_config;
    crypto::Bytes32 m_peerPrivate{};
    crypto::Bytes32 m_peerPublic{};
    std::unique_ptr<wgengine::wireguard::WireGuardTunnel> m_peer;
    wgengine::wireguard::WireGuardTunnel::PeerId m_peerId = 0;
};

TEST_F(Given_PeerProtocol, When_HostedPathStops_Then_NativePathUsesEstablishedSession)
{
    ConfigureNative();
    auto& session = m_injector.create<wgengine::Session&>();
    auto derp =
        std::make_unique<fakes::derp::FakeConnection>(DerpToken, derp::DerpClient::Packet{});
    auto& transport = *derp;
    (void)session.AddDerpConnection(1, std::move(derp));
    const auto plaintext = Plaintext(false);

    m_injector.create<hosted::Client&>().Stop();
    session.SendPacketTo(m_peerPublic, plaintext);
    ASSERT_EQ(transport.Sent.size(), 1U);
    const auto received = m_peer->ProcessPacket(m_peerId, transport.Sent.front().Payload);
    ASSERT_TRUE(received.has_value());

    EXPECT_EQ(received->Plaintext, plaintext);
    EXPECT_TRUE(received->Reply.empty());
    EXPECT_TRUE(session.PeerStats(m_peerPublic)->WireGuardSession);
}

TEST_F(Given_PeerProtocol, When_PacketIsReplayedOnNativePath_Then_SharedReplayWindowRejectsIt)
{
    const auto encrypted = m_peer->Encrypt(m_peerId, Plaintext(true));
    auto& client = m_injector.create<hosted::Client&>();
    ASSERT_EQ(client.Process(ServerPacket(encrypted)).LocalPackets.size(), 1U);
    ConfigureNative();
    auto& session = m_injector.create<wgengine::Session&>();
    (void)session.AddDerpConnection(
        1,
        std::make_unique<fakes::derp::FakeConnection>(
            DerpToken, derp::DerpClient::Packet{.Source = m_peerPublic, .Payload = encrypted}));
    auto& events = dynamic_cast<fakes::FakeEventLoop&>(m_injector.create<base::EventLoop&>());
    events.Next.Events.push_back({.Token = DerpToken, .Readiness = base::EventReadiness::Readable});

    client.Stop();
    const auto received = session.Wait(MaximumEvents, MaximumPackets, MaximumPacketSize);

    EXPECT_TRUE(received.WireGuardEvents.empty());
}

TEST_F(Given_PeerProtocol, When_HostedPathRestarts_Then_SessionAndDiscoOwnerArePreserved)
{
    auto& client = m_injector.create<hosted::Client&>();
    auto& protocol = m_injector.create<wgengine::PeerProtocol&>();
    const auto* disco = &client.Disco();
    const auto plaintext = Plaintext(true);
    const auto encrypted = m_peer->Encrypt(m_peerId, plaintext);

    client.Stop();
    (void)client.Start(m_config);
    const auto received = client.Process(ServerPacket(encrypted));
    ASSERT_EQ(received.LocalPackets.size(), 1U);

    EXPECT_EQ(received.LocalPackets.front().Bytes, plaintext);
    EXPECT_EQ(&client.Disco(), disco);
    EXPECT_EQ(&client.Disco(), &protocol.Disco());
}

TEST_F(Given_PeerProtocol, When_AnotherIdentityIsStarted_Then_ExistingSessionIsPreserved)
{
    auto& client = m_injector.create<hosted::Client&>();
    auto other = m_config;
    other.NodePrivateKey = crypto::GeneratePrivateKey();
    other.NodePublicKey = crypto::X25519PublicFromPrivate(other.NodePrivateKey);
    std::optional<wgengine::PeerProtocolError> error;
    const auto plaintext = Plaintext(true);

    try
    {
        (void)client.Start(other);
    }
    catch (const wgengine::PeerProtocolException& exception)
    {
        error = exception.Error();
    }
    const auto received = client.Process(ServerPacket(m_peer->Encrypt(m_peerId, plaintext)));
    ASSERT_EQ(received.LocalPackets.size(), 1U);

    EXPECT_EQ(error, wgengine::PeerProtocolError::IdentityChanged);
    EXPECT_EQ(received.LocalPackets.front().Bytes, plaintext);
}

TEST_F(Given_PeerProtocol, When_SessionResets_Then_NewTransportUsesEstablishedProtocol)
{
    ConfigureNative();
    auto& session = m_injector.create<wgengine::Session&>();
    auto& protocol = m_injector.create<wgengine::PeerProtocol&>();
    const auto* disco = &protocol.Disco();
    auto old = std::make_unique<fakes::derp::FakeConnection>(DerpToken, derp::DerpClient::Packet{});
    (void)session.AddDerpConnection(1, std::move(old));
    const auto plaintext = Plaintext(false);

    m_injector.create<hosted::Client&>().Stop();
    session.Reset();
    const auto cleared = session.DerpConnectionCount() == 0 && !session.PeerStats(m_peerPublic);
    ConfigureNative();
    auto replacement =
        std::make_unique<fakes::derp::FakeConnection>(DerpToken, derp::DerpClient::Packet{});
    auto& transport = *replacement;
    (void)session.AddDerpConnection(1, std::move(replacement));
    session.SendPacketTo(m_peerPublic, plaintext);
    ASSERT_EQ(transport.Sent.size(), 1U);
    const auto received = m_peer->ProcessPacket(m_peerId, transport.Sent.front().Payload);
    ASSERT_TRUE(received);

    EXPECT_TRUE(cleared);
    EXPECT_EQ(&protocol.Disco(), disco);
    EXPECT_EQ(received->Plaintext, plaintext);
    EXPECT_TRUE(received->Reply.empty());
}

TEST_F(Given_PeerProtocol, When_AccountResets_Then_ClearsProtocolAndAcceptsNewIdentity)
{
    auto& client = m_injector.create<hosted::Client&>();
    auto& protocol = m_injector.create<wgengine::PeerProtocol&>();
    auto other = m_config;
    other.NodePrivateKey = crypto::GeneratePrivateKey();
    other.NodePublicKey = crypto::X25519PublicFromPrivate(other.NodePrivateKey);
    other.DiscoPrivateKey = crypto::GeneratePrivateKey();

    client.Stop();
    m_injector.create<wgengine::Session&>().Reset();
    protocol.Reset();
    const auto cleared = !protocol.Initialized();
    const auto hello = client.Start(other);
    const auto stats = protocol.Router().HasSession(m_peerPublic);

    EXPECT_TRUE(cleared);
    EXPECT_FALSE(hello.empty());
    EXPECT_TRUE(protocol.Initialized());
    EXPECT_FALSE(stats);
    EXPECT_EQ(protocol.Disco().PublicKey(), crypto::X25519PublicFromPrivate(other.DiscoPrivateKey));
}

} // namespace
} // namespace tailgate::tests
