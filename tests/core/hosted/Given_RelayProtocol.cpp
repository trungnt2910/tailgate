#include <cstdint>
#include <format>
#include <stdexcept>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/relay/RelayProtocol.h>

namespace
{

class MemoryStream final : public tailgate::IByteStream
{
public:
    explicit MemoryStream(std::string input) : Input(input.begin(), input.end())
    {
    }

    std::optional<std::size_t> TryWriteSome(const std::uint8_t* data, std::size_t size) override
    {
        Output.insert(Output.end(), data, data + size);
        return size;
    }

    std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t maxBytes) override
    {
        const std::size_t count = std::min(maxBytes, Input.size() - Offset);
        std::vector<std::uint8_t> result(Input.begin() + static_cast<std::ptrdiff_t>(Offset),
                                         Input.begin() +
                                             static_cast<std::ptrdiff_t>(Offset + count));
        Offset += count;
        return result;
    }

    std::vector<std::uint8_t> Input;
    std::vector<std::uint8_t> Output;
    std::size_t Offset = 0;
};

TEST(Given_FragmentedRelayFrame, When_Decoding_Then_PayloadIsReturnedAfterFinalFragment)
{
    const tailgate::relay::Frame source{tailgate::relay::MessageType::ClientPacket, {1, 2, 3, 4}};
    const std::vector<std::uint8_t> encoded = tailgate::relay::Encode(source);
    tailgate::relay::Decoder decoder;

    decoder.Feed(encoded.data(), 5);
    const std::optional<tailgate::relay::Frame> incomplete = decoder.Next();
    decoder.Feed(encoded.data() + 5, encoded.size() - 5);
    const std::optional<tailgate::relay::Frame> complete = decoder.Next();

    EXPECT_FALSE(incomplete.has_value());
    EXPECT_TRUE(complete.has_value());
    EXPECT_EQ(tailgate::relay::MessageType::ClientPacket, complete->Type);
    EXPECT_EQ(source.Payload, complete->Payload);
    EXPECT_EQ(0U, decoder.BufferedBytes());
}

TEST(Given_CoalescedRelayFrames, When_Decoding_Then_EachFrameIsReturned)
{
    std::vector<std::uint8_t> encoded =
        tailgate::relay::Encode({tailgate::relay::MessageType::Heartbeat, {}});
    const std::vector<std::uint8_t> second =
        tailgate::relay::Encode({tailgate::relay::MessageType::ServerPacket, {9, 8}});
    encoded.insert(encoded.end(), second.begin(), second.end());
    tailgate::relay::Decoder decoder;

    decoder.Feed(encoded);
    const std::optional<tailgate::relay::Frame> firstFrame = decoder.Next();
    const std::optional<tailgate::relay::Frame> secondFrame = decoder.Next();

    EXPECT_TRUE(firstFrame.has_value());
    EXPECT_EQ(tailgate::relay::MessageType::Heartbeat, firstFrame->Type);
    EXPECT_TRUE(secondFrame.has_value());
    EXPECT_EQ(tailgate::relay::MessageType::ServerPacket, secondFrame->Type);
    EXPECT_EQ((std::vector<std::uint8_t>{9, 8}), secondFrame->Payload);
}

TEST(Given_TailnetDnsRelayFrame, When_RoundTripping_Then_PacketIsPreserved)
{
    const tailgate::relay::Frame source{.Type = tailgate::relay::MessageType::TailnetDnsQuery,
                                        .Payload = {0x45, 0, 0, 28}};

    const std::vector<std::uint8_t> encoded = tailgate::relay::Encode(source);
    tailgate::relay::Decoder decoder;
    decoder.Feed(encoded);
    const std::optional<tailgate::relay::Frame> decoded = decoder.Next();

    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->Type, tailgate::relay::MessageType::TailnetDnsQuery);
    EXPECT_EQ(decoded->Payload, source.Payload);
}

TEST(Given_InvalidRelayMagic, When_Decoding_Then_FrameIsRejected)
{
    std::vector<std::uint8_t> encoded =
        tailgate::relay::Encode({tailgate::relay::MessageType::Heartbeat, {}});
    encoded[0] = 0;
    tailgate::relay::Decoder decoder;

    decoder.Feed(encoded);

    EXPECT_THROW((void)decoder.Next(), std::runtime_error);
}

TEST(Given_EncryptedPeerPacket, When_RoundTripping_Then_PeerAndWireGuardDataArePreserved)
{
    tailgate::relay::PeerPacket packet;
    packet.Peer[0] = 42;
    packet.Payload = {4, 0, 0, 0, 9, 8, 7};
    packet.Control = true;
    packet.Disco = true;
    packet.EndpointAddress = 0x01020304;
    packet.EndpointPort = 41641;

    const std::vector<std::uint8_t> encoded = tailgate::relay::EncodePeerPacket(packet);
    const tailgate::relay::PeerPacket decoded = tailgate::relay::DecodePeerPacket(encoded);

    EXPECT_EQ(packet.Peer, decoded.Peer);
    EXPECT_EQ(packet.Payload, decoded.Payload);
    EXPECT_EQ(packet.Control, decoded.Control);
    EXPECT_EQ(packet.Disco, decoded.Disco);
    EXPECT_EQ(packet.EndpointAddress, decoded.EndpointAddress);
    EXPECT_EQ(packet.EndpointPort, decoded.EndpointPort);
}

TEST(Given_PeerPacketWithoutWireGuardData, When_Decoding_Then_ItIsRejected)
{
    const std::vector<std::uint8_t> truncated(tailgate::protocol::Bytes32{}.size());

    const auto decode = [&]()
    {
        (void)tailgate::relay::DecodePeerPacket(truncated);
    };

    EXPECT_THROW(decode(), std::runtime_error);
}

TEST(Given_DerpAuthenticationChallenge, When_RoundTripping_Then_RequestIsPreserved)
{
    tailgate::relay::DerpAuthenticationChallenge source;
    source.RequestId = 0x1020304050607080ULL;
    source.ServerKey[7] = 42;

    const std::vector<std::uint8_t> encoded = tailgate::relay::EncodeDerpChallenge(source);
    const tailgate::relay::DerpAuthenticationChallenge decoded =
        tailgate::relay::DecodeDerpChallenge(encoded);

    EXPECT_EQ(source.RequestId, decoded.RequestId);
    EXPECT_EQ(source.ServerKey, decoded.ServerKey);
}

TEST(Given_DerpAuthenticationResponse, When_RoundTripping_Then_EnvelopeIsPreserved)
{
    const tailgate::relay::DerpAuthenticationResponse source{.RequestId = 17,
                                                             .ClientInfo = {1, 2, 3, 4}};

    const std::vector<std::uint8_t> encoded = tailgate::relay::EncodeDerpResponse(source);
    const tailgate::relay::DerpAuthenticationResponse decoded =
        tailgate::relay::DecodeDerpResponse(encoded);

    EXPECT_EQ(source.RequestId, decoded.RequestId);
    EXPECT_EQ(source.ClientInfo, decoded.ClientInfo);
}

TEST(Given_RelayAuthentication, When_RoundTripping_Then_HostIdentityIsPreserved)
{
    tailgate::relay::Authentication source;
    source.Tailnet = "example.ts.net";
    source.NodeId = 42;
    source.Hostname = "watch";
    source.OperatingSystem = "Windows";
    source.OperatingSystemVersion = "10.0.15063";
    source.NodePublicKey[0] = 42;

    const std::vector<std::uint8_t> encoded = tailgate::relay::EncodeAuthentication(source);
    const tailgate::relay::Authentication decoded = tailgate::relay::DecodeAuthentication(encoded);

    const std::string serialized(encoded.begin(), encoded.end());

    EXPECT_EQ(source.Tailnet, decoded.Tailnet);
    EXPECT_EQ(source.NodeId, decoded.NodeId);
    EXPECT_EQ(source.Hostname, decoded.Hostname);
    EXPECT_EQ(source.OperatingSystem, decoded.OperatingSystem);
    EXPECT_EQ(source.OperatingSystemVersion, decoded.OperatingSystemVersion);
    EXPECT_EQ(source.NodePublicKey, decoded.NodePublicKey);
    EXPECT_EQ(source.ClientNonce, decoded.ClientNonce);
    EXPECT_EQ(source.ClientProof, decoded.ClientProof);
    EXPECT_EQ(serialized.find("PrivateKey"), std::string::npos);
    EXPECT_EQ(serialized.find("AuthKey"), std::string::npos);
    EXPECT_EQ(serialized.find("ReconnectSecret"), std::string::npos);
}

TEST(Given_RelayChallenge, When_RoundTripping_Then_ServerIdentityIsPreserved)
{
    tailgate::relay::Challenge source;
    source.RelayPublicKey[0] = 42;
    source.ServerNonce[31] = 17;

    const std::vector<std::uint8_t> encoded = tailgate::relay::EncodeChallenge(source);
    const tailgate::relay::Challenge decoded = tailgate::relay::DecodeChallenge(encoded);

    EXPECT_EQ(source.RelayPublicKey, decoded.RelayPublicKey);
    EXPECT_EQ(source.ServerNonce, decoded.ServerNonce);
}

TEST(Given_ClientAndRelayKeys, When_CreatingProofs_Then_BothSidesAgree)
{
    const tailgate::protocol::Bytes32 clientPrivate = tailgate::protocol::GeneratePrivateKey();
    const tailgate::protocol::Bytes32 relayPrivate = tailgate::protocol::GeneratePrivateKey();
    const tailgate::protocol::Bytes32 clientPublic =
        tailgate::protocol::X25519PublicFromPrivate(clientPrivate);
    const tailgate::protocol::Bytes32 relayPublic =
        tailgate::protocol::X25519PublicFromPrivate(relayPrivate);
    const tailgate::protocol::Bytes32 serverNonce = tailgate::protocol::GeneratePrivateKey();
    const tailgate::protocol::Bytes32 clientNonce = tailgate::protocol::GeneratePrivateKey();

    const tailgate::protocol::Bytes32 clientProof =
        tailgate::relay::CreateClientProof(clientPrivate, relayPublic, serverNonce, clientNonce);
    const tailgate::protocol::Bytes32 expectedClientProof =
        tailgate::relay::CreateClientProof(relayPrivate, clientPublic, serverNonce, clientNonce);
    const tailgate::protocol::Bytes32 serverProof =
        tailgate::relay::CreateServerProof(relayPrivate, clientPublic, serverNonce, clientNonce);
    const tailgate::protocol::Bytes32 expectedServerProof =
        tailgate::relay::CreateServerProof(clientPrivate, relayPublic, serverNonce, clientNonce);

    EXPECT_TRUE(tailgate::relay::ProofMatches(expectedClientProof, clientProof));
    EXPECT_TRUE(tailgate::relay::ProofMatches(expectedServerProof, serverProof));
}

TEST(Given_ChangedRelayNonce, When_VerifyingClientProof_Then_ProofIsRejected)
{
    const tailgate::protocol::Bytes32 clientPrivate = tailgate::protocol::GeneratePrivateKey();
    const tailgate::protocol::Bytes32 relayPrivate = tailgate::protocol::GeneratePrivateKey();
    const tailgate::protocol::Bytes32 clientPublic =
        tailgate::protocol::X25519PublicFromPrivate(clientPrivate);
    const tailgate::protocol::Bytes32 relayPublic =
        tailgate::protocol::X25519PublicFromPrivate(relayPrivate);
    const tailgate::protocol::Bytes32 serverNonce = tailgate::protocol::GeneratePrivateKey();
    tailgate::protocol::Bytes32 changedNonce = serverNonce;
    changedNonce[0] ^= 1U;
    const tailgate::protocol::Bytes32 clientNonce = tailgate::protocol::GeneratePrivateKey();

    const tailgate::protocol::Bytes32 proof =
        tailgate::relay::CreateClientProof(clientPrivate, relayPublic, serverNonce, clientNonce);
    const tailgate::protocol::Bytes32 replayed =
        tailgate::relay::CreateClientProof(relayPrivate, clientPublic, changedNonce, clientNonce);

    EXPECT_FALSE(tailgate::relay::ProofMatches(replayed, proof));
}

TEST(Given_IncompleteRelayAuthentication, When_Decoding_Then_ItIsRejected)
{
    const std::vector<std::uint8_t> encoded{'{', '}'};

    const auto decode = [&]()
    {
        (void)tailgate::relay::DecodeAuthentication(encoded);
    };

    EXPECT_THROW(decode(), std::exception);
}

TEST(Given_RelaySession, When_RoundTripping_Then_PublicMetadataIsPreserved)
{
    tailgate::relay::Session source;
    source.Tailnet = "example.ts.net";
    source.RelayHostName = "relay-host";
    source.RelayHostAddress = "100.64.0.1";
    source.ServerProof[0] = 7;

    const std::vector<std::uint8_t> encoded = tailgate::relay::EncodeSession(source);
    const tailgate::relay::Session decoded = tailgate::relay::DecodeSession(encoded);

    const std::string serialized(encoded.begin(), encoded.end());

    EXPECT_EQ(source.Tailnet, decoded.Tailnet);
    EXPECT_EQ(source.RelayHostName, decoded.RelayHostName);
    EXPECT_EQ(source.RelayHostAddress, decoded.RelayHostAddress);
    EXPECT_EQ(source.ServerProof, decoded.ServerProof);
    EXPECT_EQ(serialized.find("PrivateKey"), std::string::npos);
    EXPECT_EQ(serialized.find("ReconnectSecret"), std::string::npos);
}

TEST(Given_RelayNetworkMap, When_RoundTripping_Then_SelfIdentityIsPreserved)
{
    tailgate::control::NetworkConfig source;
    source.SelfNodeId = 42;
    source.SelfKey = "nodekey:0102";
    source.SelfAddress = "100.64.0.42";
    source.SelfName = "watch.example.ts.net";
    source.Domain = "example.ts.net";
    source.UserProfiles.push_back(tailgate::control::UserProfile{.Id = 7,
                                                                 .LoginName = "tagged-devices",
                                                                 .DisplayName = "Tagged Devices",
                                                                 .ProfilePicUrl = {}});
    tailgate::control::PeerConfig peer;
    peer.NodeId = 101;
    peer.OwnerId = 7;
    peer.Owner = "Tagged Devices";
    source.Peers.push_back(peer);

    const std::vector<std::uint8_t> encoded = tailgate::relay::EncodeNetworkConfig(source);
    const tailgate::control::NetworkConfig decoded = tailgate::relay::DecodeNetworkConfig(encoded);

    EXPECT_EQ(decoded.SelfNodeId, source.SelfNodeId);
    EXPECT_EQ(decoded.SelfKey, source.SelfKey);
    EXPECT_EQ(decoded.Domain, source.Domain);
    ASSERT_EQ(decoded.UserProfiles.size(), 1U);
    ASSERT_EQ(decoded.Peers.size(), 1U);
    EXPECT_EQ(decoded.UserProfiles.front().DisplayName, "Tagged Devices");
    EXPECT_EQ(decoded.Peers.front().OwnerId, 7U);
    EXPECT_EQ(decoded.Peers.front().Owner, "Tagged Devices");
}

TEST(Given_LargeRelayNetworkMap, When_RoundTripping_Then_ItIsNotTruncated)
{
    tailgate::control::NetworkConfig source;
    source.SelfNodeId = 42;
    source.SelfKey = "nodekey:0102";
    source.SelfAddress = "100.64.0.42";
    source.SelfName = "watch.example.ts.net";
    source.Domain = "example.ts.net";
    for (std::uint64_t index = 1; index <= 100; ++index)
    {
        tailgate::control::PeerConfig peer;
        peer.NodeId = index;
        peer.Name = std::format("peer-{}.example.ts.net", index);
        peer.Address = "100.64.0.1";
        peer.Key = "nodekey:" + std::string(64, 'a');
        source.Peers.push_back(std::move(peer));
    }

    const std::vector<std::uint8_t> encoded = tailgate::relay::EncodeNetworkConfig(source);
    const tailgate::control::NetworkConfig decoded = tailgate::relay::DecodeNetworkConfig(encoded);

    EXPECT_GT(encoded.size(), 4096U);
    EXPECT_EQ(decoded.Peers.size(), source.Peers.size());
}

TEST(Given_TailgateHttpUpgrade, When_ServerAccepts_Then_ProtocolIsSwitched)
{
    MemoryStream stream(
        "POST /tailgate HTTP/1.1\r\nHost: relay.example.com\r\nConnection: Upgrade\r\n"
        "Upgrade: tailgate\r\n\r\n");

    tailgate::relay::AcceptHttpUpgrade(stream);

    const std::string response(stream.Output.begin(), stream.Output.end());
    EXPECT_TRUE(response.rfind("HTTP/1.1 101 ", 0) == 0);
}

TEST(Given_RelayFrameCoalescedWithHttpUpgrade, When_ClientUpgrades_Then_FrameIsPreserved)
{
    const tailgate::relay::Frame challenge{.Type = tailgate::relay::MessageType::ServerChallenge,
                                           .Payload = {1, 2, 3}};
    const std::vector<std::uint8_t> encoded = tailgate::relay::Encode(challenge);
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tailgate\r\n\r\n";
    response.append(reinterpret_cast<const char*>(encoded.data()), encoded.size());
    MemoryStream stream(std::move(response));
    tailgate::relay::Decoder decoder;

    decoder.Feed(tailgate::relay::RequestHttpUpgrade(stream, "relay.example.com:443"));
    const std::optional<tailgate::relay::Frame> decoded = decoder.Next();

    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->Type, challenge.Type);
    EXPECT_EQ(decoded->Payload, challenge.Payload);
}

TEST(Given_UnknownHttpPath, When_ServerAccepts_Then_RequestIsRejected)
{
    MemoryStream stream(
        "POST /other HTTP/1.1\r\nHost: relay.example.com\r\nUpgrade: tailgate\r\n\r\n");

    const auto accept = [&]()
    {
        tailgate::relay::AcceptHttpUpgrade(stream);
    };

    EXPECT_THROW(accept(), std::runtime_error);
    const std::string response(stream.Output.begin(), stream.Output.end());
    EXPECT_TRUE(response.rfind("HTTP/1.1 404 ", 0) == 0);
}

} // namespace
