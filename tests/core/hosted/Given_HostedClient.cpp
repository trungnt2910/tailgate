#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/types/netmap/NetworkMap.h>
#include <tailgate/wgengine/wireguard/Tunnel.h>

namespace
{

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

TEST(Given_HostedClient, When_Started_Then_InitialNetworkMapFrameIsReturned)
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

TEST(Given_HostedClient, When_KeepAliveIsBuilt_Then_HeartbeatFrameIsReturned)
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

TEST(Given_HostedClient, When_NetworkMapIsUpdated_Then_RelayUpdateFrameIsReturned)
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

TEST(Given_HostedClient, When_HeartbeatArrives_Then_HeartbeatIsReturned)
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

TEST(Given_HostedClient, When_DerpChallengeArrives_Then_AuthenticatedResponseIsReturned)
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

TEST(Given_HostedClient,
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
    const std::optional<tailgate::hosted::Frame> response = decoder.Next();
    ASSERT_TRUE(response.has_value());
    const tailgate::hosted::PeerPacket responsePacket =
        tailgate::hosted::ProtocolCodec::DecodePeerPacket(response->Payload());

    EXPECT_EQ(response->Type(), tailgate::hosted::MessageType::ClientPacket);
    EXPECT_EQ(responsePacket.Peer(), secondPeerPublic);
}

TEST(Given_HostedClient, When_DirectDiscoPongArrives_Then_VerifiedEndpointIsAcknowledged)
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

    EXPECT_TRUE(result.Pong.has_value());
    EXPECT_TRUE(acknowledgementTypeMatches);
    EXPECT_TRUE(endpoint.has_value());
    EXPECT_EQ(endpoint ? endpoint->Peer() : tailgate::crypto::Bytes32{}, peerNodePublic);
    EXPECT_EQ(endpoint ? endpoint->Endpoint() : tailgate::net::Endpoint{},
              tailgate::net::Endpoint(directAddress, DirectPort));
    EXPECT_FALSE(decoder.Next().has_value());
}

TEST(Given_HostedClient, When_NetworkMapRetainsIdentity_Then_CoreUpdatesItsState)
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

TEST(Given_HostedClient, When_NetworkMapChangesIdentity_Then_TypedErrorIsReturned)
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

TEST(Given_HostedClient, When_Stopped_Then_SessionStateIsReleased)
{
    tailgate::hosted::Client subject;
    (void)subject.Start(MakeConfig());
    ASSERT_TRUE(subject.Active());

    subject.Stop();

    EXPECT_FALSE(subject.Active());
    EXPECT_TRUE(subject.Encapsulate({1, 2, 3}).empty());
}

TEST(Given_HostedClient, When_DiscoIsRequestedWhileStopped_Then_TypedErrorIsReturned)
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

} // namespace
