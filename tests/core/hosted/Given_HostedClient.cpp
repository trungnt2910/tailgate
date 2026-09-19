#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/PacketFraming.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/IpAddress.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/netmap/NetworkMap.h>
#include <tailgate/wgengine/wireguard/Tunnel.h>

namespace tailgate::tests
{
namespace
{

class Given_HostedClient : public testing::Test
{
protected:
    Given_HostedClient()
        : m_peerPrivate(crypto::GeneratePrivateKey()),
          m_peerPublic(crypto::X25519PublicFromPrivate(m_peerPrivate)),
          m_peer(m_peerPrivate)
    {
        hosted::ClientConfig config;
        config.NodePrivateKey = crypto::GeneratePrivateKey();
        config.NodePublicKey = crypto::X25519PublicFromPrivate(config.NodePrivateKey);
        config.DiscoPrivateKey = crypto::GeneratePrivateKey();
        config.Network.SelfAddress("192.0.2.1");
        config.Network.SelfAddresses({"192.0.2.1", "2001:db8::1"});
        types::netmap::PeerConfig remote;
        remote.Key("nodekey:" + crypto::BytesToHex(m_peerPublic.data(), m_peerPublic.size()));
        remote.Address("192.0.2.2");
        remote.Addresses({"192.0.2.2", "2001:db8::2"});
        config.Network.Peers({remote});
        m_peerId = m_peer.AddPeer(config.NodePublicKey);
        (void)m_client.Start(config);
    }

    static hosted::Frame ServerPacket(const crypto::Bytes32& label,
                                      const std::vector<std::uint8_t>& payload,
                                      net::Endpoint endpoint = net::Endpoint(
                                          net::Ipv4Address::FromOctets(198, 51, 100, 1), 41641))
    {
        const hosted::PeerPacket packet(
            label, payload, false, false, endpoint.Address().HostOrder(), endpoint.Port());
        return hosted::Frame(hosted::MessageType::ServerPacket,
                             hosted::ProtocolCodec::EncodePeerPacket(packet));
    }

    void Establish()
    {
        const auto started =
            m_client.Process(ServerPacket(m_peerPublic, m_peer.CreateHandshake(m_peerId)));
        hosted::Decoder decoder;
        decoder.Feed(started.RemoteOutput);
        const auto endpoint = decoder.Next();
        ASSERT_TRUE(endpoint.has_value());
        ASSERT_EQ(endpoint->Type(), hosted::MessageType::PeerEndpoint);
        const auto response = decoder.Next();
        ASSERT_TRUE(response.has_value());
        ASSERT_EQ(response->Type(), hosted::MessageType::ClientPacket);
        const auto transport = hosted::ProtocolCodec::DecodePeerPacket(response->Payload());
        ASSERT_TRUE(m_peer.ProcessPacket(m_peerId, transport.Payload()).has_value());
        ASSERT_TRUE(m_peer.HasSession(m_peerId));
        // Confirm the responder's keypair before testing outbound data.
        const auto confirmation = m_peer.Encrypt(m_peerId, {});
        (void)m_client.Process(ServerPacket(m_peerPublic, confirmation));
    }

    crypto::Bytes32 m_peerPrivate;
    crypto::Bytes32 m_peerPublic;
    wgengine::wireguard::WireGuardTunnel m_peer;
    wgengine::wireguard::WireGuardTunnel::PeerId m_peerId = 0;
    hosted::Client m_client;
};

tailgate::hosted::ClientConfig MakeConfig()
{
    const tailgate::crypto::Bytes32 nodePrivateKey = tailgate::crypto::GeneratePrivateKey();
    tailgate::types::netmap::NetworkConfig network;
    network.Domain("example.ts.net");
    network.SelfNodeId(42);
    network.SelfKey("nodekey:fake-client-key");
    network.SelfAddress("100.64.0.1");
    return tailgate::hosted::ClientConfig{
        .NodePrivateKey = nodePrivateKey,
        .NodePublicKey = tailgate::crypto::X25519PublicFromPrivate(nodePrivateKey),
        .DiscoPrivateKey = tailgate::crypto::GeneratePrivateKey(),
        .Network = std::move(network),
        .ExitNode = {},
    };
}

tailgate::types::netmap::PeerConfig MakePeer(const tailgate::crypto::Bytes32& publicKey,
                                             std::string address)
{
    tailgate::types::netmap::PeerConfig peer;
    peer.Key("nodekey:" + tailgate::crypto::BytesToHex(publicKey.data(), publicKey.size()));
    peer.Address(std::move(address));
    return peer;
}

TEST_F(Given_HostedClient, When_Started_Then_InitialNetworkMapFrameIsReturned)
{
    tailgate::hosted::Client subject;
    tailgate::hosted::ClientConfig config = MakeConfig();
    const auto expectedNodeId = config.Network.SelfNodeId();
    const std::string expectedDomain = config.Network.Domain();

    const std::vector<std::uint8_t> output = subject.Start(std::move(config));
    tailgate::hosted::Decoder decoder;
    decoder.Feed(output);
    const std::optional<tailgate::hosted::Frame> frame = decoder.Next();
    ASSERT_TRUE(frame.has_value());
    const tailgate::types::netmap::NetworkConfig network =
        tailgate::hosted::ProtocolCodec::DecodeNetworkConfig(frame->Payload());

    EXPECT_EQ(frame->Type(), tailgate::hosted::MessageType::NetworkMap);
    EXPECT_EQ(network.SelfNodeId(), expectedNodeId);
    EXPECT_EQ(network.Domain(), expectedDomain);
    EXPECT_FALSE(decoder.Next().has_value());
}

TEST_F(Given_HostedClient, When_KeepAliveIsBuilt_Then_HeartbeatFrameIsReturned)
{
    tailgate::hosted::Client subject;
    (void)subject.Start(MakeConfig());

    const std::vector<std::uint8_t> output = subject.BuildKeepAlive();
    tailgate::hosted::Decoder decoder;
    decoder.Feed(output);
    const std::optional<tailgate::hosted::Frame> frame = decoder.Next();
    ASSERT_TRUE(frame.has_value());

    EXPECT_EQ(frame->Type(), tailgate::hosted::MessageType::Heartbeat);
    EXPECT_TRUE(frame->Payload().empty());
    EXPECT_FALSE(decoder.Next().has_value());
}

TEST_F(Given_HostedClient, When_KeepAliveIsRequestedBeforeStart_Then_NoTransportBytesAreProduced)
{
    hosted::Client subject;

    const auto output = subject.BuildKeepAlive();

    EXPECT_TRUE(output.empty());
}

TEST_F(Given_HostedClient, When_KeepAliveIsRequestedAfterStop_Then_NoTransportBytesAreProduced)
{
    hosted::Client subject;
    (void)subject.Start(MakeConfig());
    subject.Stop();

    const auto output = subject.BuildKeepAlive();

    EXPECT_TRUE(output.empty());
}

TEST_F(Given_HostedClient,
       When_KeepAliveArrivesDuringReconnect_Then_NewRelayStreamHasNoMissingPrefix)
{
    constexpr std::size_t PacketCapacity = 1500;
    hosted::Client subject;
    (void)subject.Start(MakeConfig());
    subject.Stop();
    hosted::PacketEncoder encoder;
    hosted::Decoder relay;

    encoder.Queue(subject.BuildKeepAlive());
    const auto obsoleteTransportPacket = encoder.Next(PacketCapacity);
    (void)subject.Start(MakeConfig());
    encoder.Queue(subject.BuildKeepAlive());
    relay.Feed(encoder.Next(PacketCapacity));
    const auto firstFrame = relay.Next();
    const bool heartbeatReceived =
        firstFrame && firstFrame->Type() == hosted::MessageType::Heartbeat;

    EXPECT_TRUE(obsoleteTransportPacket.empty());
    EXPECT_TRUE(heartbeatReceived);
    EXPECT_FALSE(encoder.HasPending());
    EXPECT_FALSE(relay.Next().has_value());
}

TEST_F(Given_HostedClient, When_DataPathReadyArrives_Then_ReadinessIsReported)
{
    tailgate::hosted::Client subject;
    (void)subject.Start(MakeConfig());
    const tailgate::hosted::Frame ready(tailgate::hosted::MessageType::DataPathReady, {});

    const tailgate::hosted::ClientProcessResult result = subject.Process(ready);

    EXPECT_TRUE(result.DataPathReady);
    EXPECT_TRUE(result.RemoteOutput.empty());
}

TEST_F(Given_HostedClient,
       When_ServerEndpointCandidatesArrive_Then_DirectDiscoveryStartsImmediately)
{
    constexpr std::uint16_t PeerPort = 41641;
    constexpr std::uint16_t ServerPort = 51234;
    tailgate::hosted::Client subject;
    tailgate::hosted::ClientConfig config = MakeConfig();
    const tailgate::crypto::Bytes32 peerNodePrivate = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 peerNodePublic =
        tailgate::crypto::X25519PublicFromPrivate(peerNodePrivate);
    const tailgate::disco::Disco peerDisco(tailgate::crypto::GeneratePrivateKey(), peerNodePublic);
    tailgate::types::netmap::PeerConfig peer = MakePeer(peerNodePublic, "192.0.2.2");
    peer.DiscoKey("discokey:" + tailgate::crypto::BytesToHex(peerDisco.PublicKey().data(),
                                                             peerDisco.PublicKey().size()));
    peer.Endpoints({"192.0.2.10:41641"});
    peer.Online(true);
    config.Network.Peers({std::move(peer)});
    (void)subject.Start(std::move(config));
    const tailgate::net::Endpoint serverEndpoint(
        tailgate::net::Ipv4Address::FromOctets(198, 51, 100, 20), ServerPort);
    const tailgate::hosted::Frame candidates(
        tailgate::hosted::MessageType::ServerEndpointCandidates,
        tailgate::hosted::ProtocolCodec::EncodeServerEndpointCandidates(
            tailgate::hosted::ServerEndpointCandidates({serverEndpoint})));

    const tailgate::hosted::ClientProcessResult result = subject.Process(candidates);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(result.RemoteOutput);
    const std::optional<tailgate::hosted::Frame> relayPingFrame = decoder.Next();
    const std::optional<tailgate::hosted::Frame> directPingFrame = decoder.Next();
    const std::optional<tailgate::hosted::Frame> callMeMaybeFrame = decoder.Next();
    const std::optional<tailgate::hosted::PeerPacket> directPing =
        directPingFrame ? std::optional(tailgate::hosted::ProtocolCodec::DecodePeerPacket(
                              directPingFrame->Payload()))
                        : std::nullopt;
    const std::optional<tailgate::hosted::PeerPacket> callMeMaybe =
        callMeMaybeFrame ? std::optional(tailgate::hosted::ProtocolCodec::DecodePeerPacket(
                               callMeMaybeFrame->Payload()))
                         : std::nullopt;
    const std::optional<tailgate::disco::Disco::Message> advertised =
        callMeMaybe ? peerDisco.Parse(callMeMaybe->Payload()) : std::nullopt;
    ASSERT_TRUE(directPing);
    ASSERT_TRUE(advertised);

    EXPECT_TRUE(relayPingFrame.has_value());
    EXPECT_TRUE(directPingFrame.has_value());
    EXPECT_TRUE(callMeMaybeFrame.has_value());
    EXPECT_EQ(directPing->EndpointAddress(),
              tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 10).HostOrder());
    EXPECT_EQ(directPing->EndpointPort(), PeerPort);
    EXPECT_EQ(advertised->Endpoints, (std::vector<tailgate::net::Endpoint>{serverEndpoint}));
    EXPECT_FALSE(result.DataPathReady);
    EXPECT_FALSE(decoder.Next().has_value());
}

TEST_F(Given_HostedClient, When_NetworkMapIsUpdated_Then_RelayUpdateFrameIsReturned)
{
    tailgate::hosted::Client subject;
    tailgate::hosted::ClientConfig config = MakeConfig();
    tailgate::types::netmap::NetworkConfig next = config.Network;
    next.SelfName("client.example.ts.net");
    (void)subject.Start(std::move(config));

    const std::vector<std::uint8_t> output = subject.UpdateNetworkMap(next);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(output);
    const std::optional<tailgate::hosted::Frame> frame = decoder.Next();
    ASSERT_TRUE(frame.has_value());
    const tailgate::types::netmap::NetworkConfig relayed =
        tailgate::hosted::ProtocolCodec::DecodeNetworkConfig(frame->Payload());

    EXPECT_EQ(frame->Type(), tailgate::hosted::MessageType::NetworkMap);
    EXPECT_EQ(relayed.SelfName(), next.SelfName());
    EXPECT_FALSE(decoder.Next().has_value());
}

TEST_F(Given_HostedClient, When_HeartbeatArrives_Then_HeartbeatIsReturned)
{
    tailgate::hosted::Client subject;
    (void)subject.Start(MakeConfig());
    const tailgate::hosted::Frame heartbeat(tailgate::hosted::MessageType::Heartbeat, {});

    const tailgate::hosted::ClientProcessResult result = subject.Process(heartbeat);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(result.RemoteOutput);
    const std::optional<tailgate::hosted::Frame> response = decoder.Next();

    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response->Type(), tailgate::hosted::MessageType::Heartbeat);
    EXPECT_TRUE(response->Payload().empty());
    EXPECT_FALSE(decoder.Next().has_value());
}

TEST_F(Given_HostedClient, When_DerpChallengeArrives_Then_AuthenticatedResponseIsReturned)
{
    constexpr std::uint64_t RequestId = 77;
    tailgate::hosted::Client subject;
    (void)subject.Start(MakeConfig());
    const tailgate::hosted::Frame challenge(
        tailgate::hosted::MessageType::DerpChallenge,
        tailgate::hosted::ProtocolCodec::EncodeDerpChallenge(
            tailgate::hosted::DerpAuthenticationChallenge(RequestId,
                                                          tailgate::crypto::GeneratePrivateKey())));

    const tailgate::hosted::ClientProcessResult result = subject.Process(challenge);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(result.RemoteOutput);
    const std::optional<tailgate::hosted::Frame> frame = decoder.Next();
    ASSERT_TRUE(frame.has_value());
    const tailgate::hosted::DerpAuthenticationResponse response =
        tailgate::hosted::ProtocolCodec::DecodeDerpResponse(frame->Payload());

    EXPECT_EQ(frame->Type(), tailgate::hosted::MessageType::DerpResponse);
    EXPECT_EQ(response.RequestId(), RequestId);
    EXPECT_FALSE(response.ClientInfo().empty());
}

TEST_F(Given_HostedClient,
       When_DirectWireGuardPacketHasIncorrectRelayHint_Then_CryptographicPeerIsUsed)
{
    tailgate::hosted::Client subject;
    tailgate::hosted::ClientConfig config = MakeConfig();
    tailgate::crypto::Bytes32 firstPeerPrivate{};
    firstPeerPrivate[1] = 1;
    tailgate::crypto::Bytes32 secondPeerPrivate{};
    secondPeerPrivate[1] = 2;
    const tailgate::crypto::Bytes32 firstPeerPublic =
        tailgate::crypto::X25519PublicFromPrivate(firstPeerPrivate);
    const tailgate::crypto::Bytes32 secondPeerPublic =
        tailgate::crypto::X25519PublicFromPrivate(secondPeerPrivate);
    config.Network.Peers(
        {MakePeer(firstPeerPublic, "192.0.2.2"), MakePeer(secondPeerPublic, "192.0.2.3")});
    const tailgate::crypto::Bytes32 clientPublic = config.NodePublicKey;
    (void)subject.Start(std::move(config));
    tailgate::wgengine::wireguard::WireGuardTunnel secondPeer(secondPeerPrivate);
    const auto client = secondPeer.AddPeer(clientPublic);
    const std::vector<std::uint8_t> initiation = secondPeer.CreateHandshake(client);
    const tailgate::hosted::PeerPacket mislabeled(
        firstPeerPublic,
        initiation,
        true,
        false,
        tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 10).HostOrder(),
        41641);
    const tailgate::hosted::Frame input(
        tailgate::hosted::MessageType::ServerPacket,
        tailgate::hosted::ProtocolCodec::EncodePeerPacket(mislabeled));

    const tailgate::hosted::ClientProcessResult result = subject.Process(input);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(result.RemoteOutput);
    const auto endpointFrame = decoder.Next();
    ASSERT_TRUE(endpointFrame);
    const auto verified = hosted::ProtocolCodec::DecodePeerEndpoint(endpointFrame->Payload());
    const auto response = decoder.Next();
    ASSERT_TRUE(response);
    const auto responsePacket = hosted::ProtocolCodec::DecodePeerPacket(response->Payload());

    EXPECT_EQ(endpointFrame->Type(), hosted::MessageType::PeerEndpoint);
    EXPECT_EQ(response->Type(), hosted::MessageType::ClientPacket);
    EXPECT_EQ(responsePacket.Peer(), secondPeerPublic);
    EXPECT_EQ(verified.Peer(), secondPeerPublic);
}

TEST_F(Given_HostedClient, When_DirectDiscoPongArrives_Then_VerifiedEndpointIsAcknowledged)
{
    constexpr std::uint16_t DirectPort = 41641;
    const tailgate::net::Ipv4Address directAddress =
        tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 10);
    tailgate::hosted::Client subject;
    tailgate::hosted::ClientConfig config = MakeConfig();
    const tailgate::crypto::Bytes32 clientDiscoPrivate = config.DiscoPrivateKey;
    const tailgate::crypto::Bytes32 clientNodePublic = config.NodePublicKey;
    const tailgate::crypto::Bytes32 peerNodePrivate = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 peerNodePublic =
        tailgate::crypto::X25519PublicFromPrivate(peerNodePrivate);
    tailgate::disco::Disco clientDisco(clientDiscoPrivate, clientNodePublic);
    tailgate::disco::Disco peerDisco(peerNodePrivate, peerNodePublic);
    tailgate::types::netmap::PeerConfig peer = MakePeer(peerNodePublic, "192.0.2.2");
    peer.DiscoKey("discokey:" + tailgate::crypto::BytesToHex(peerDisco.PublicKey().data(),
                                                             peerDisco.PublicKey().size()));
    config.Network.Peers({std::move(peer)});
    (void)subject.Start(std::move(config));
    const tailgate::disco::Disco::TransactionId transaction = clientDisco.NewTransactionId();
    const tailgate::hosted::PeerPacket pong(
        peerNodePublic,
        peerDisco.BuildPong(clientDisco.PublicKey(), transaction, directAddress, DirectPort),
        false,
        true,
        directAddress.HostOrder(),
        DirectPort);
    const tailgate::hosted::Frame input(tailgate::hosted::MessageType::ServerPacket,
                                        tailgate::hosted::ProtocolCodec::EncodePeerPacket(pong));

    const tailgate::hosted::ClientProcessResult result = subject.Process(input);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(result.RemoteOutput);
    const std::optional<tailgate::hosted::Frame> acknowledgement = decoder.Next();
    const bool acknowledgementTypeMatches =
        acknowledgement && acknowledgement->Type() == tailgate::hosted::MessageType::PeerEndpoint;
    const std::optional<tailgate::hosted::PeerEndpoint> endpoint =
        acknowledgementTypeMatches
            ? std::optional(
                  tailgate::hosted::ProtocolCodec::DecodePeerEndpoint(acknowledgement->Payload()))
            : std::nullopt;
    ASSERT_TRUE(endpoint);

    EXPECT_TRUE(result.Pong.has_value());
    EXPECT_TRUE(acknowledgementTypeMatches);
    EXPECT_EQ(endpoint->Peer(), peerNodePublic);
    EXPECT_EQ(endpoint->Endpoint(), tailgate::net::Endpoint(directAddress, DirectPort));
    EXPECT_FALSE(decoder.Next().has_value());
}

TEST_F(Given_HostedClient,
       When_FreshDiscoPongConfirmsSameEndpoint_Then_RelayReceivesNewConfirmation)
{
    const net::Endpoint direct(net::Ipv4Address::FromOctets(192, 0, 2, 10), 41641);
    hosted::Client subject;
    auto config = MakeConfig();
    disco::Disco clientDisco(config.DiscoPrivateKey, config.NodePublicKey);
    const auto peerPrivate = crypto::GeneratePrivateKey();
    const auto peerPublic = crypto::X25519PublicFromPrivate(peerPrivate);
    disco::Disco peerDisco(peerPrivate, peerPublic);
    auto peer = MakePeer(peerPublic, "192.0.2.2");
    peer.DiscoKey("discokey:" +
                  crypto::BytesToHex(peerDisco.PublicKey().data(), peerDisco.PublicKey().size()));
    config.Network.Peers({std::move(peer)});
    (void)subject.Start(std::move(config));
    const auto freshPong = [&]()
    {
        const hosted::PeerPacket packet(peerPublic,
                                        peerDisco.BuildPong(clientDisco.PublicKey(),
                                                            clientDisco.NewTransactionId(),
                                                            direct.Address(),
                                                            direct.Port()),
                                        false,
                                        true,
                                        direct.Address().HostOrder(),
                                        direct.Port());
        return hosted::Frame(hosted::MessageType::ServerPacket,
                             hosted::ProtocolCodec::EncodePeerPacket(packet));
    };
    const auto initial = subject.Process(freshPong());
    ASSERT_FALSE(initial.RemoteOutput.empty());
    const auto input = freshPong();

    const auto result = subject.Process(input);
    hosted::Decoder decoder;
    decoder.Feed(result.RemoteOutput);
    const auto acknowledgement = decoder.Next();
    const bool isEndpoint =
        acknowledgement && acknowledgement->Type() == hosted::MessageType::PeerEndpoint;
    const auto endpoint =
        isEndpoint
            ? std::optional(hosted::ProtocolCodec::DecodePeerEndpoint(acknowledgement->Payload()))
            : std::nullopt;
    ASSERT_TRUE(endpoint);

    EXPECT_TRUE(result.Pong.has_value());
    EXPECT_TRUE(isEndpoint);
    EXPECT_EQ(endpoint->Peer(), peerPublic);
    EXPECT_EQ(endpoint->Endpoint(), direct);
    EXPECT_FALSE(decoder.Next().has_value());
}

TEST_F(Given_HostedClient, When_DerpDiscoPingArrives_Then_PongUsesIngressRoute)
{
    constexpr std::uint64_t RouteToken = 42;
    constexpr std::uint16_t ConfiguredDerpRegion = 5;
    constexpr std::uint16_t IngressDerpRegion = 7;
    tailgate::hosted::Client subject;
    tailgate::hosted::ClientConfig config = MakeConfig();
    config.Network.DerpRegion(ConfiguredDerpRegion);
    const tailgate::crypto::Bytes32 clientDiscoPrivate = config.DiscoPrivateKey;
    const tailgate::crypto::Bytes32 clientNodePublic = config.NodePublicKey;
    const tailgate::crypto::Bytes32 peerNodePrivate = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 peerNodePublic =
        tailgate::crypto::X25519PublicFromPrivate(peerNodePrivate);
    tailgate::disco::Disco clientDisco(clientDiscoPrivate, clientNodePublic);
    tailgate::disco::Disco peerDisco(tailgate::crypto::GeneratePrivateKey(), peerNodePublic);
    tailgate::types::netmap::PeerConfig peer = MakePeer(peerNodePublic, "192.0.2.2");
    peer.DiscoKey("discokey:" + tailgate::crypto::BytesToHex(peerDisco.PublicKey().data(),
                                                             peerDisco.PublicKey().size()));
    config.Network.Peers({std::move(peer)});
    (void)subject.Start(std::move(config));
    const tailgate::disco::Disco::TransactionId transaction = peerDisco.NewTransactionId();
    const tailgate::hosted::PeerPacket ping(
        peerNodePublic,
        peerDisco.BuildPing(clientDisco.PublicKey(), transaction),
        false,
        true,
        0,
        0,
        tailgate::hosted::DerpRoute(RouteToken, IngressDerpRegion));
    const tailgate::hosted::Frame input(tailgate::hosted::MessageType::ServerPacket,
                                        tailgate::hosted::ProtocolCodec::EncodePeerPacket(ping));

    const tailgate::hosted::ClientProcessResult result = subject.Process(input);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(result.RemoteOutput);
    const std::optional<tailgate::hosted::Frame> response = decoder.Next();
    const std::optional<tailgate::hosted::PeerPacket> responsePacket =
        response && response->Type() == tailgate::hosted::MessageType::ClientPacket
            ? std::optional(tailgate::hosted::ProtocolCodec::DecodePeerPacket(response->Payload()))
            : std::nullopt;
    const std::optional<tailgate::disco::Disco::Message> pong =
        responsePacket ? peerDisco.Parse(responsePacket->Payload()) : std::nullopt;

    ASSERT_TRUE(responsePacket.has_value());
    ASSERT_TRUE(pong.has_value());
    ASSERT_TRUE(pong->SourceEndpoint.has_value());
    ASSERT_TRUE(responsePacket->DerpIngressRoute().has_value());
    EXPECT_EQ(pong->Type, tailgate::disco::Disco::MessageType::Pong);
    EXPECT_EQ(pong->Transaction, transaction);
    EXPECT_EQ(
        *pong->SourceEndpoint,
        tailgate::net::Endpoint(tailgate::disco::Disco::DerpMagicIpv4Address, IngressDerpRegion));
    EXPECT_EQ(*responsePacket->DerpIngressRoute(),
              tailgate::hosted::DerpRoute(RouteToken, IngressDerpRegion));
    EXPECT_FALSE(decoder.Next().has_value());
}

TEST_F(Given_HostedClient, When_NetworkMapRetainsIdentity_Then_CoreUpdatesItsState)
{
    tailgate::hosted::Client subject;
    tailgate::hosted::ClientConfig config = MakeConfig();
    tailgate::types::netmap::NetworkConfig next = config.Network;
    next.SelfName("client.example.ts.net");
    (void)subject.Start(std::move(config));
    const tailgate::hosted::Frame update(
        tailgate::hosted::MessageType::NetworkMap,
        tailgate::hosted::ProtocolCodec::EncodeNetworkConfig(next));

    const tailgate::hosted::ClientProcessResult result = subject.Process(update);

    EXPECT_TRUE(result.NetworkMapChanged);
    EXPECT_EQ(subject.Network().SelfName(), next.SelfName());
    EXPECT_TRUE(result.LocalPackets.empty());
    EXPECT_TRUE(result.RemoteOutput.empty());
}

TEST_F(Given_HostedClient, When_NetworkMapChangesIdentity_Then_TypedErrorIsReturned)
{
    tailgate::hosted::Client subject;
    tailgate::hosted::ClientConfig config = MakeConfig();
    tailgate::types::netmap::NetworkConfig next = config.Network;
    next.SelfNodeId(next.SelfNodeId() + 1);
    (void)subject.Start(std::move(config));
    const tailgate::hosted::Frame update(
        tailgate::hosted::MessageType::NetworkMap,
        tailgate::hosted::ProtocolCodec::EncodeNetworkConfig(next));
    std::optional<tailgate::hosted::ClientError> error;

    try
    {
        (void)subject.Process(update);
    }
    catch (const tailgate::hosted::ClientException& exception)
    {
        error = exception.Error();
    }

    EXPECT_EQ(error, tailgate::hosted::ClientError::IdentityChanged);
}

TEST_F(Given_HostedClient, When_Stopped_Then_SessionStateIsReleased)
{
    tailgate::hosted::Client subject;
    (void)subject.Start(MakeConfig());
    ASSERT_TRUE(subject.Active());

    subject.Stop();

    EXPECT_FALSE(subject.Active());
    EXPECT_TRUE(subject.Encapsulate({1, 2, 3}).empty());
}

TEST_F(Given_HostedClient, When_DiscoIsRequestedWhileStopped_Then_TypedErrorIsReturned)
{
    tailgate::hosted::Client subject;
    std::optional<tailgate::hosted::ClientError> error;

    try
    {
        (void)subject.Disco();
    }
    catch (const tailgate::hosted::ClientException& exception)
    {
        error = exception.Error();
    }

    EXPECT_EQ(error, tailgate::hosted::ClientError::NotActive);
}

TEST_F(Given_HostedClient, When_RelayMislabelsDirectData_Then_PlaintextRetainsAuthenticatedSender)
{
    ASSERT_NO_FATAL_FAILURE(Establish());
    const auto packet =
        net::packet::Ipv4Packet::Build(net::Ipv4Address::FromOctets(192, 0, 2, 2).HostOrder(),
                                       net::Ipv4Address::FromOctets(192, 0, 2, 1).HostOrder(),
                                       6,
                                       std::vector<std::uint8_t>(20));
    crypto::Bytes32 falseLabel{};
    falseLabel.fill(0x33);
    const auto frame = ServerPacket(falseLabel, m_peer.Encrypt(m_peerId, packet));

    const auto result = m_client.Process(frame);
    ASSERT_EQ(result.LocalPackets.size(), 1U);

    EXPECT_EQ(result.LocalPackets.size(), 1U);
    EXPECT_EQ(result.LocalPackets.front().Peer, m_peerPublic);
    EXPECT_EQ(result.LocalPackets.front().Bytes, packet);
}

TEST_F(Given_HostedClient, When_Ipv6PacketIsSentToExplicitPeer_Then_RouteLookupIsNotRequired)
{
    ASSERT_NO_FATAL_FAILURE(Establish());
    constexpr std::size_t Ipv6HeaderLength = 40;
    constexpr std::size_t TcpHeaderLength = 20;
    std::vector<std::uint8_t> packet(Ipv6HeaderLength + TcpHeaderLength);
    packet[0] = 0x60;
    packet[5] = TcpHeaderLength;
    packet[6] = 6;

    const auto encoded = m_client.EncapsulateTo(m_peerPublic, packet);
    hosted::Decoder decoder;
    decoder.Feed(encoded);
    const auto frame = decoder.Next();
    const auto transport =
        frame ? std::optional(hosted::ProtocolCodec::DecodePeerPacket(frame->Payload()))
              : std::nullopt;
    const auto received =
        transport ? m_peer.ProcessPacket(m_peerId, transport->Payload()) : std::nullopt;
    ASSERT_TRUE(transport);
    ASSERT_TRUE(received);

    EXPECT_EQ(transport->Peer(), m_peerPublic);
    EXPECT_EQ(received->Plaintext, packet);
}

TEST_F(Given_HostedClient,
       When_UnknownDirectSourceSendsValidHandshake_Then_AuthenticatedPeerIsReported)
{
    const auto frame = ServerPacket({}, m_peer.CreateHandshake(m_peerId));

    const auto result = m_client.Process(frame);
    hosted::Decoder decoder;
    decoder.Feed(result.RemoteOutput);
    const auto endpoint = decoder.Next();
    const auto verified =
        endpoint ? std::optional(hosted::ProtocolCodec::DecodePeerEndpoint(endpoint->Payload()))
                 : std::nullopt;
    const auto response = decoder.Next();
    ASSERT_TRUE(endpoint);
    ASSERT_TRUE(verified);
    ASSERT_TRUE(response);

    EXPECT_EQ(endpoint->Type(), hosted::MessageType::PeerEndpoint);
    EXPECT_EQ(verified->Peer(), m_peerPublic);
    EXPECT_EQ(verified->Endpoint(),
              net::Endpoint(net::Ipv4Address::FromOctets(198, 51, 100, 1), 41641));
    EXPECT_EQ(response->Type(), hosted::MessageType::ClientPacket);
}

TEST_F(Given_HostedClient, When_HostSendsIpv6ToNode_Then_CoreResolvesPeerWithoutExplicitHint)
{
    ASSERT_NO_FATAL_FAILURE(Establish());
    constexpr std::size_t Ipv6HeaderLength = 40;
    constexpr std::size_t DestinationOffset = 24;
    constexpr std::size_t TcpHeaderLength = 20;
    std::vector<std::uint8_t> packet(Ipv6HeaderLength + TcpHeaderLength);
    packet[0] = 0x60;
    packet[5] = TcpHeaderLength;
    packet[6] = 6;
    const auto destination = net::IpAddress::Parse("2001:db8::2");
    std::ranges::copy(destination.Bytes(), packet.begin() + DestinationOffset);

    const auto encoded = m_client.Encapsulate(packet);
    hosted::Decoder decoder;
    decoder.Feed(encoded);
    const auto frame = decoder.Next();
    const auto transport =
        frame ? std::optional(hosted::ProtocolCodec::DecodePeerPacket(frame->Payload()))
              : std::nullopt;
    const auto received =
        transport ? m_peer.ProcessPacket(m_peerId, transport->Payload()) : std::nullopt;
    ASSERT_TRUE(transport);
    ASSERT_TRUE(received);

    EXPECT_EQ(transport->Peer(), m_peerPublic);
    EXPECT_EQ(received->Plaintext, packet);
}

TEST_F(Given_HostedClient,
       When_PeerRoamsWithoutDisco_Then_OnlyAuthenticatedEndpointChangeIsReported)
{
    ASSERT_NO_FATAL_FAILURE(Establish());
    const net::Endpoint roaming(net::Ipv4Address::FromOctets(198, 51, 100, 2), 41642);
    const auto first = ServerPacket({}, m_peer.Encrypt(m_peerId, {}), roaming);
    const auto second = ServerPacket({}, m_peer.Encrypt(m_peerId, {}), roaming);

    const auto changed = m_client.Process(first);
    const auto unchanged = m_client.Process(second);
    hosted::Decoder decoder;
    decoder.Feed(changed.RemoteOutput);
    const auto endpoint = decoder.Next();
    const auto verified =
        endpoint ? std::optional(hosted::ProtocolCodec::DecodePeerEndpoint(endpoint->Payload()))
                 : std::nullopt;
    const auto extra = decoder.Next();
    ASSERT_TRUE(endpoint);
    ASSERT_TRUE(verified);

    EXPECT_EQ(endpoint->Type(), hosted::MessageType::PeerEndpoint);
    EXPECT_EQ(verified->Peer(), m_peerPublic);
    EXPECT_EQ(verified->Endpoint(), roaming);
    EXPECT_FALSE(extra.has_value());
    EXPECT_TRUE(unchanged.RemoteOutput.empty());
}

TEST_F(Given_HostedClient, When_UnverifiedSourceCorruptsCiphertext_Then_NoEndpointIsTrusted)
{
    ASSERT_NO_FATAL_FAILURE(Establish());
    auto encrypted = m_peer.Encrypt(m_peerId, {});
    encrypted.back() ^= 1;
    const auto frame = ServerPacket(
        {}, encrypted, net::Endpoint(net::Ipv4Address::FromOctets(198, 51, 100, 2), 41642));

    const auto result = m_client.Process(frame);

    EXPECT_TRUE(result.RemoteOutput.empty());
    EXPECT_TRUE(result.LocalPackets.empty());
}

TEST_F(Given_HostedClient, When_UnverifiedSourceReplaysCiphertext_Then_NoEndpointIsTrusted)
{
    ASSERT_NO_FATAL_FAILURE(Establish());
    const auto encrypted = m_peer.Encrypt(m_peerId, {});
    (void)m_client.Process(ServerPacket(m_peerPublic, encrypted));
    const auto frame = ServerPacket(
        {}, encrypted, net::Endpoint(net::Ipv4Address::FromOctets(198, 51, 100, 2), 41642));

    const auto result = m_client.Process(frame);

    EXPECT_TRUE(result.RemoteOutput.empty());
    EXPECT_TRUE(result.LocalPackets.empty());
}

} // namespace
} // namespace tailgate::tests
