#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/Ipv4Address.h>

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

    std::vector<std::uint8_t> Input;
    std::vector<std::uint8_t> Output;
    std::size_t Offset = 0;
};

class AvailableFrameStream final : public tailgate::base::ByteStream
{
public:
    explicit AvailableFrameStream(std::vector<std::vector<std::uint8_t>> input)
        : m_input(std::move(input))
    {
    }

    std::optional<std::size_t> TryWriteSome(const std::uint8_t*, std::size_t) override
    {
        return std::nullopt;
    }

    std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t) override
    {
        if (m_offset == m_input.size())
        {
            return std::nullopt;
        }
        return m_input[m_offset++];
    }

private:
    std::vector<std::vector<std::uint8_t>> m_input;
    std::size_t m_offset = 0;
};

TEST(Given_RelayProtocol,
     When_FragmentedRelayFrameAndDecoding_Then_PayloadIsReturnedAfterFinalFragment)
{
    const tailgate::hosted::Frame source(tailgate::hosted::MessageType::ClientPacket, {1, 2, 3, 4});
    const std::vector<std::uint8_t> encoded = source.Encode();
    tailgate::hosted::Decoder decoder;

    decoder.Feed(encoded.data(), 5);
    const std::optional<tailgate::hosted::Frame> incomplete = decoder.Next();
    decoder.Feed(encoded.data() + 5, encoded.size() - 5);
    const std::optional<tailgate::hosted::Frame> complete = decoder.Next();

    EXPECT_FALSE(incomplete.has_value());
    EXPECT_TRUE(complete.has_value());
    EXPECT_EQ(tailgate::hosted::MessageType::ClientPacket, complete->Type());
    EXPECT_EQ(source.Payload(), complete->Payload());
    EXPECT_EQ(0U, decoder.BufferedBytes());
}

TEST(Given_RelayProtocol, When_CoalescedRelayFramesAndDecoding_Then_EachFrameIsReturned)
{
    std::vector<std::uint8_t> encoded =
        tailgate::hosted::Frame(tailgate::hosted::MessageType::Heartbeat, {}).Encode();
    const std::vector<std::uint8_t> second =
        tailgate::hosted::Frame(tailgate::hosted::MessageType::ServerPacket, {9, 8}).Encode();
    encoded.insert(encoded.end(), second.begin(), second.end());
    tailgate::hosted::Decoder decoder;

    decoder.Feed(encoded);
    const std::optional<tailgate::hosted::Frame> firstFrame = decoder.Next();
    const std::optional<tailgate::hosted::Frame> secondFrame = decoder.Next();

    EXPECT_TRUE(firstFrame.has_value());
    EXPECT_EQ(tailgate::hosted::MessageType::Heartbeat, firstFrame->Type());
    EXPECT_TRUE(secondFrame.has_value());
    EXPECT_EQ(tailgate::hosted::MessageType::ServerPacket, secondFrame->Type());
    EXPECT_EQ((std::vector<std::uint8_t>{9, 8}), secondFrame->Payload());
}

TEST(Given_RelayProtocol, When_MaximumRelayPayloadAndEncoding_Then_ExactFrameLimitIsUsed)
{
    const std::vector<std::uint8_t> payload(tailgate::hosted::Frame::MaximumPayloadSize, 0x42);
    const tailgate::hosted::Frame frame(tailgate::hosted::MessageType::NetworkMap, payload);

    const std::vector<std::uint8_t> encoded = frame.Encode();

    EXPECT_EQ(encoded.size(), tailgate::hosted::Frame::MaximumEncodedSize);
}

TEST(Given_RelayProtocol, When_RelayPayloadExceedsMaximumAndEncoding_Then_FrameIsRejected)
{
    const std::vector<std::uint8_t> payload(tailgate::hosted::Frame::MaximumPayloadSize + 1U, 0x42);
    const tailgate::hosted::Frame frame(tailgate::hosted::MessageType::NetworkMap, payload);

    const auto encode = [&]()
    {
        (void)frame.Encode();
    };

    EXPECT_THROW(encode(), std::runtime_error);
}

TEST(Given_RelayProtocol, When_TailnetDnsRelayFrameAndRoundTripping_Then_PacketIsPreserved)
{
    const tailgate::hosted::Frame source(tailgate::hosted::MessageType::TailnetDnsQuery,
                                         {0x45, 0, 0, 28});

    const std::vector<std::uint8_t> encoded = source.Encode();
    tailgate::hosted::Decoder decoder;
    decoder.Feed(encoded);
    const std::optional<tailgate::hosted::Frame> decoded = decoder.Next();

    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->Type(), tailgate::hosted::MessageType::TailnetDnsQuery);
    EXPECT_EQ(decoded->Payload(), source.Payload());
}

TEST(Given_RelayProtocol, When_InvalidRelayMagicAndDecoding_Then_FrameIsRejected)
{
    std::vector<std::uint8_t> encoded =
        tailgate::hosted::Frame(tailgate::hosted::MessageType::Heartbeat, {}).Encode();
    encoded[0] = 0;
    tailgate::hosted::Decoder decoder;

    decoder.Feed(encoded);

    EXPECT_THROW((void)decoder.Next(), std::runtime_error);
}

TEST(Given_RelayProtocol,
     When_EncryptedPeerPacketAndRoundTripping_Then_PeerAndWireGuardDataArePreserved)
{
    tailgate::crypto::Bytes32 peer{};
    peer[0] = 42;
    const tailgate::hosted::PeerPacket packet(
        peer,
        {4, 0, 0, 0, 9, 8, 7},
        true,
        true,
        tailgate::net::Ipv4Address::FromOctets(1, 2, 3, 4).HostOrder(),
        41641);

    const std::vector<std::uint8_t> encoded =
        tailgate::hosted::ProtocolCodec::EncodePeerPacket(packet);
    const tailgate::hosted::PeerPacket decoded =
        tailgate::hosted::ProtocolCodec::DecodePeerPacket(encoded);

    EXPECT_EQ(packet.Peer(), decoded.Peer());
    EXPECT_EQ(packet.Payload(), decoded.Payload());
    EXPECT_EQ(packet.Control(), decoded.Control());
    EXPECT_EQ(packet.Disco(), decoded.Disco());
    EXPECT_EQ(packet.EndpointAddress(), decoded.EndpointAddress());
    EXPECT_EQ(packet.EndpointPort(), decoded.EndpointPort());
}

TEST(Given_RelayProtocol, When_PeerPacketWithoutWireGuardDataAndDecoding_Then_ItIsRejected)
{
    const std::vector<std::uint8_t> truncated(tailgate::crypto::Bytes32{}.size());

    const auto decode = [&]()
    {
        (void)tailgate::hosted::ProtocolCodec::DecodePeerPacket(truncated);
    };

    EXPECT_THROW(decode(), std::runtime_error);
}

TEST(Given_RelayProtocol, When_VerifiedPeerEndpointAndRoundTripping_Then_RouteIsPreserved)
{
    tailgate::crypto::Bytes32 peer{};
    peer[0] = 42;
    const tailgate::net::Endpoint endpoint(tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 10),
                                           41641);
    const tailgate::hosted::PeerEndpoint source(peer, endpoint);

    const std::vector<std::uint8_t> encoded =
        tailgate::hosted::ProtocolCodec::EncodePeerEndpoint(source);
    const tailgate::hosted::PeerEndpoint decoded =
        tailgate::hosted::ProtocolCodec::DecodePeerEndpoint(encoded);

    EXPECT_EQ(decoded.Peer(), peer);
    EXPECT_EQ(decoded.Endpoint(), endpoint);
}

TEST(Given_RelayProtocol, When_DerpAuthenticationChallengeAndRoundTripping_Then_RequestIsPreserved)
{
    tailgate::crypto::Bytes32 serverKey{};
    serverKey[7] = 42;
    const tailgate::hosted::DerpAuthenticationChallenge source(0x1020304050607080ULL, serverKey);

    const std::vector<std::uint8_t> encoded =
        tailgate::hosted::ProtocolCodec::EncodeDerpChallenge(source);
    const tailgate::hosted::DerpAuthenticationChallenge decoded =
        tailgate::hosted::ProtocolCodec::DecodeDerpChallenge(encoded);

    EXPECT_EQ(source.RequestId(), decoded.RequestId());
    EXPECT_EQ(source.ServerKey(), decoded.ServerKey());
}

TEST(Given_RelayProtocol, When_DerpAuthenticationResponseAndRoundTripping_Then_EnvelopeIsPreserved)
{
    const tailgate::hosted::DerpAuthenticationResponse source(17, {1, 2, 3, 4});

    const std::vector<std::uint8_t> encoded =
        tailgate::hosted::ProtocolCodec::EncodeDerpResponse(source);
    const tailgate::hosted::DerpAuthenticationResponse decoded =
        tailgate::hosted::ProtocolCodec::DecodeDerpResponse(encoded);

    EXPECT_EQ(source.RequestId(), decoded.RequestId());
    EXPECT_EQ(source.ClientInfo(), decoded.ClientInfo());
}

TEST(Given_RelayProtocol, When_RelayAuthenticationAndRoundTripping_Then_HostIdentityIsPreserved)
{
    tailgate::crypto::Bytes32 nodePublicKey{};
    nodePublicKey[0] = 42;
    const tailgate::hosted::Authentication source(
        "example.ts.net", 42, "watch", "Windows", "10.0.15063", nodePublicKey, {}, {});

    const std::vector<std::uint8_t> encoded =
        tailgate::hosted::ProtocolCodec::EncodeAuthentication(source);
    const tailgate::hosted::Authentication decoded =
        tailgate::hosted::ProtocolCodec::DecodeAuthentication(encoded);

    const std::string serialized(encoded.begin(), encoded.end());

    EXPECT_EQ(source.Tailnet(), decoded.Tailnet());
    EXPECT_EQ(source.NodeId(), decoded.NodeId());
    EXPECT_EQ(source.Hostname(), decoded.Hostname());
    EXPECT_EQ(source.OperatingSystem(), decoded.OperatingSystem());
    EXPECT_EQ(source.OperatingSystemVersion(), decoded.OperatingSystemVersion());
    EXPECT_EQ(source.NodePublicKey(), decoded.NodePublicKey());
    EXPECT_EQ(source.ClientNonce(), decoded.ClientNonce());
    EXPECT_EQ(source.ClientProof(), decoded.ClientProof());
    EXPECT_EQ(serialized.find("PrivateKey"), std::string::npos);
    EXPECT_EQ(serialized.find("AuthKey"), std::string::npos);
    EXPECT_EQ(serialized.find("ReconnectSecret"), std::string::npos);
}

TEST(Given_RelayProtocol, When_RelayChallengeAndRoundTripping_Then_ServerIdentityIsPreserved)
{
    tailgate::crypto::Bytes32 relayPublicKey{};
    tailgate::crypto::Bytes32 serverNonce{};
    relayPublicKey[0] = 42;
    serverNonce[31] = 17;
    const tailgate::hosted::Challenge source(relayPublicKey, serverNonce);

    const std::vector<std::uint8_t> encoded =
        tailgate::hosted::ProtocolCodec::EncodeChallenge(source);
    const tailgate::hosted::Challenge decoded =
        tailgate::hosted::ProtocolCodec::DecodeChallenge(encoded);

    EXPECT_EQ(source.RelayPublicKey(), decoded.RelayPublicKey());
    EXPECT_EQ(source.ServerNonce(), decoded.ServerNonce());
}

TEST(Given_RelayProtocol, When_ClientAndRelayKeysAndCreatingProofs_Then_BothSidesAgree)
{
    const tailgate::crypto::Bytes32 clientPrivate = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 relayPrivate = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 clientPublic =
        tailgate::crypto::X25519PublicFromPrivate(clientPrivate);
    const tailgate::crypto::Bytes32 relayPublic =
        tailgate::crypto::X25519PublicFromPrivate(relayPrivate);
    const tailgate::crypto::Bytes32 serverNonce = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 clientNonce = tailgate::crypto::GeneratePrivateKey();

    const tailgate::crypto::Bytes32 clientProof =
        tailgate::hosted::CreateClientProof(clientPrivate, relayPublic, serverNonce, clientNonce);
    const tailgate::crypto::Bytes32 expectedClientProof =
        tailgate::hosted::CreateClientProof(relayPrivate, clientPublic, serverNonce, clientNonce);
    const tailgate::crypto::Bytes32 serverProof =
        tailgate::hosted::CreateServerProof(relayPrivate, clientPublic, serverNonce, clientNonce);
    const tailgate::crypto::Bytes32 expectedServerProof =
        tailgate::hosted::CreateServerProof(clientPrivate, relayPublic, serverNonce, clientNonce);

    EXPECT_TRUE(tailgate::hosted::ProofMatches(expectedClientProof, clientProof));
    EXPECT_TRUE(tailgate::hosted::ProofMatches(expectedServerProof, serverProof));
}

TEST(Given_RelayProtocol, When_ChangedRelayNonceAndVerifyingClientProof_Then_ProofIsRejected)
{
    const tailgate::crypto::Bytes32 clientPrivate = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 relayPrivate = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 clientPublic =
        tailgate::crypto::X25519PublicFromPrivate(clientPrivate);
    const tailgate::crypto::Bytes32 relayPublic =
        tailgate::crypto::X25519PublicFromPrivate(relayPrivate);
    const tailgate::crypto::Bytes32 serverNonce = tailgate::crypto::GeneratePrivateKey();
    tailgate::crypto::Bytes32 changedNonce = serverNonce;
    changedNonce[0] ^= 1U;
    const tailgate::crypto::Bytes32 clientNonce = tailgate::crypto::GeneratePrivateKey();

    const tailgate::crypto::Bytes32 proof =
        tailgate::hosted::CreateClientProof(clientPrivate, relayPublic, serverNonce, clientNonce);
    const tailgate::crypto::Bytes32 replayed =
        tailgate::hosted::CreateClientProof(relayPrivate, clientPublic, changedNonce, clientNonce);

    EXPECT_FALSE(tailgate::hosted::ProofMatches(replayed, proof));
}

TEST(Given_RelayProtocol, When_IncompleteRelayAuthenticationAndDecoding_Then_ItIsRejected)
{
    const std::vector<std::uint8_t> encoded{'{', '}'};

    const auto decode = [&]()
    {
        (void)tailgate::hosted::ProtocolCodec::DecodeAuthentication(encoded);
    };

    EXPECT_THROW(decode(), std::exception);
}

TEST(Given_RelayProtocol, When_RelaySessionAndRoundTripping_Then_PublicMetadataIsPreserved)
{
    tailgate::crypto::Bytes32 serverProof{};
    serverProof[0] = 7;
    const tailgate::hosted::Session source(
        "example.ts.net", "relay-host", "100.64.0.1", serverProof);

    const std::vector<std::uint8_t> encoded =
        tailgate::hosted::ProtocolCodec::EncodeSession(source);
    const tailgate::hosted::Session decoded =
        tailgate::hosted::ProtocolCodec::DecodeSession(encoded);

    const std::string serialized(encoded.begin(), encoded.end());

    EXPECT_EQ(source.Tailnet(), decoded.Tailnet());
    EXPECT_EQ(source.RelayHostName(), decoded.RelayHostName());
    EXPECT_EQ(source.RelayHostAddress(), decoded.RelayHostAddress());
    EXPECT_EQ(source.ServerProof(), decoded.ServerProof());
    EXPECT_EQ(serialized.find("PrivateKey"), std::string::npos);
    EXPECT_EQ(serialized.find("ReconnectSecret"), std::string::npos);
}

TEST(Given_RelayProtocol, When_RelayNetworkMapAndRoundTripping_Then_SelfIdentityIsPreserved)
{
    tailgate::types::netmap::NetworkConfig source;
    source.SelfNodeId(42);
    source.SelfKey("nodekey:0102");
    source.SelfAddress("100.64.0.42");
    source.SelfName("watch.example.ts.net");
    source.Domain("example.ts.net");
    source.UserProfiles({tailgate::types::netmap::UserProfile{.Id = 7,
                                                              .LoginName = "tagged-devices",
                                                              .DisplayName = "Tagged Devices",
                                                              .ProfilePicUrl = {}}});
    tailgate::types::netmap::PeerConfig peer;
    peer.NodeId(101);
    peer.OwnerId(7);
    peer.Owner("Tagged Devices");
    source.Peers({peer});

    const std::vector<std::uint8_t> encoded =
        tailgate::hosted::ProtocolCodec::EncodeNetworkConfig(source);
    const tailgate::types::netmap::NetworkConfig decoded =
        tailgate::hosted::ProtocolCodec::DecodeNetworkConfig(encoded);

    EXPECT_EQ(decoded.SelfNodeId(), source.SelfNodeId());
    EXPECT_EQ(decoded.SelfKey(), source.SelfKey());
    EXPECT_EQ(decoded.Domain(), source.Domain());
    ASSERT_EQ(decoded.UserProfiles().size(), 1U);
    ASSERT_EQ(decoded.Peers().size(), 1U);
    EXPECT_EQ(decoded.UserProfiles().front().DisplayName, "Tagged Devices");
    EXPECT_EQ(decoded.Peers().front().OwnerId(), 7U);
    EXPECT_EQ(decoded.Peers().front().Owner(), "Tagged Devices");
}

TEST(Given_RelayProtocol, When_LargeRelayNetworkMapAndRoundTripping_Then_ItIsNotTruncated)
{
    tailgate::types::netmap::NetworkConfig source;
    source.SelfNodeId(42);
    source.SelfKey("nodekey:0102");
    source.SelfAddress("100.64.0.42");
    source.SelfName("watch.example.ts.net");
    source.Domain("example.ts.net");
    std::vector<tailgate::types::netmap::PeerConfig> peers;
    for (std::uint64_t index = 1; index <= 100; ++index)
    {
        tailgate::types::netmap::PeerConfig peer;
        peer.NodeId(index);
        peer.Name(std::format("peer-{}.example.ts.net", index));
        peer.Address("100.64.0.1");
        peer.Key("nodekey:" + std::string(64, 'a'));
        peers.push_back(std::move(peer));
    }
    source.Peers(std::move(peers));

    const std::vector<std::uint8_t> encoded =
        tailgate::hosted::ProtocolCodec::EncodeNetworkConfig(source);
    const tailgate::types::netmap::NetworkConfig decoded =
        tailgate::hosted::ProtocolCodec::DecodeNetworkConfig(encoded);

    EXPECT_GT(encoded.size(), 4096U);
    EXPECT_EQ(decoded.Peers().size(), source.Peers().size());
}

TEST(Given_RelayProtocol, When_TailgateHttpUpgradeAndServerAccepts_Then_ProtocolIsSwitched)
{
    MemoryByteStream stream(
        "POST /tailgate HTTP/1.1\r\nHost: relay.example.com\r\nConnection: Upgrade\r\n"
        "Upgrade: tailgate\r\n\r\n");

    tailgate::hosted::AcceptHttpUpgrade(stream);

    const std::string response(stream.Output.begin(), stream.Output.end());
    EXPECT_TRUE(response.rfind("HTTP/1.1 101 ", 0) == 0);
}

TEST(Given_RelayProtocol,
     When_RelayFrameCoalescedWithHttpUpgradeAndClientUpgrades_Then_FrameIsPreserved)
{
    const tailgate::hosted::Frame challenge(tailgate::hosted::MessageType::ServerChallenge,
                                            {1, 2, 3});
    const std::vector<std::uint8_t> encoded = challenge.Encode();
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tailgate\r\n\r\n";
    response.append(reinterpret_cast<const char*>(encoded.data()), encoded.size());
    MemoryByteStream stream(std::move(response));
    tailgate::hosted::Decoder decoder;

    decoder.Feed(tailgate::hosted::RequestHttpUpgrade(stream, "relay.example.com:443"));
    const std::optional<tailgate::hosted::Frame> decoded = decoder.Next();

    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->Type(), challenge.Type());
    EXPECT_EQ(decoded->Payload(), challenge.Payload());
}

TEST(Given_RelayProtocol, When_UnknownHttpPathAndServerAccepts_Then_RequestIsRejected)
{
    MemoryByteStream stream(
        "POST /other HTTP/1.1\r\nHost: relay.example.com\r\nUpgrade: tailgate\r\n\r\n");

    const auto accept = [&]()
    {
        tailgate::hosted::AcceptHttpUpgrade(stream);
    };

    EXPECT_THROW(accept(), std::runtime_error);
    const std::string response(stream.Output.begin(), stream.Output.end());
    EXPECT_TRUE(response.rfind("HTTP/1.1 404 ", 0) == 0);
}

TEST(Given_RelayProtocol, When_MultipleAvailableFramesAreRead_Then_AllFramesAreDrained)
{
    constexpr std::size_t FrameCount = 32;
    std::vector<std::vector<std::uint8_t>> input;
    for (std::size_t index = 0; index < FrameCount; ++index)
    {
        input.push_back(tailgate::hosted::Frame(tailgate::hosted::MessageType::ServerPacket,
                                                {static_cast<std::uint8_t>(index)})
                            .Encode());
    }
    AvailableFrameStream stream(std::move(input));
    tailgate::hosted::Decoder decoder;

    const tailgate::hosted::DecoderReadResult result = decoder.ReadAvailable(stream, 16U * 1024U);

    EXPECT_EQ(result.Status, tailgate::hosted::DecoderReadStatus::WouldBlock);
    EXPECT_EQ(result.Frames.size(), FrameCount);
    EXPECT_EQ(decoder.BufferedBytes(), 0U);
}

} // namespace
