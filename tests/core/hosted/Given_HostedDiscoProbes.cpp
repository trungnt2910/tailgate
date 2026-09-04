#include <gtest/gtest.h>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/disco/Disco.h>
#include <tailgate/hosted/DiscoProbes.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace
{

[[maybe_unused]] tailgate::types::netmap::PeerConfig
MakeDiscoPeer(const tailgate::crypto::Bytes32& nodePublicKey,
              const tailgate::crypto::Bytes32& discoPublicKey)
{
    tailgate::types::netmap::PeerConfig peer;
    peer.Key("nodekey:" + tailgate::crypto::BytesToHex(nodePublicKey.data(), nodePublicKey.size()));
    peer.DiscoKey("discokey:" +
                  tailgate::crypto::BytesToHex(discoPublicKey.data(), discoPublicKey.size()));
    peer.Online(true);
    return peer;
}

} // namespace

TEST(Given_HostedDiscoProbes, When_OnlineDiscoPeerAndBuildingDiscoProbes_Then_PingTargetsThatPeer)
{
    const auto senderNode = tailgate::crypto::GeneratePrivateKey();
    const auto peerNode = tailgate::crypto::GeneratePrivateKey();
    const tailgate::disco::Disco sender(tailgate::crypto::GeneratePrivateKey(),
                                        tailgate::crypto::X25519PublicFromPrivate(senderNode));
    const tailgate::disco::Disco receiver(tailgate::crypto::GeneratePrivateKey(),
                                          tailgate::crypto::X25519PublicFromPrivate(peerNode));
    const tailgate::crypto::Bytes32 peerNodePublic =
        tailgate::crypto::X25519PublicFromPrivate(peerNode);
    const std::vector<tailgate::types::netmap::PeerConfig> peers{
        MakeDiscoPeer(peerNodePublic, receiver.PublicKey())};

    const std::vector<tailgate::hosted::PeerPacket> probes =
        tailgate::hosted::BuildDiscoProbes(sender, peers, {});
    const std::optional<tailgate::disco::Disco::Message> message =
        probes.empty() ? std::nullopt : receiver.Parse(probes.front().Payload());
    const bool targetsPeer = !probes.empty() && probes.front().Peer() == peerNodePublic;
    const bool isDisco = !probes.empty() && probes.front().Disco();
    const bool isPing =
        message.has_value() && message->Type == tailgate::disco::Disco::MessageType::Ping;
    const bool identifiesSender = message.has_value() && message->Sender == sender.PublicKey();

    EXPECT_EQ(probes.size(), 1U);
    EXPECT_TRUE(message.has_value());
    EXPECT_TRUE(targetsPeer);
    EXPECT_TRUE(isDisco);
    EXPECT_TRUE(isPing);
    EXPECT_TRUE(identifiesSender);
}

TEST(Given_HostedDiscoProbes, When_OfflineDiscoPeerAndBuildingDiscoProbes_Then_NoPingIsBuilt)
{
    const tailgate::disco::Disco sender(
        tailgate::crypto::GeneratePrivateKey(),
        tailgate::crypto::X25519PublicFromPrivate(tailgate::crypto::GeneratePrivateKey()));
    tailgate::types::netmap::PeerConfig peer = MakeDiscoPeer(
        tailgate::crypto::X25519PublicFromPrivate(tailgate::crypto::GeneratePrivateKey()),
        sender.PublicKey());
    peer.Online(false);
    const std::vector<tailgate::types::netmap::PeerConfig> peers{peer};

    const std::vector<tailgate::hosted::PeerPacket> probes =
        tailgate::hosted::BuildDiscoProbes(sender, peers, {});

    EXPECT_TRUE(probes.empty());
}

TEST(Given_HostedDiscoProbes, When_PeerWithMalformedKeysAndBuildingDiscoProbes_Then_NoPingIsBuilt)
{
    const tailgate::disco::Disco sender(
        tailgate::crypto::GeneratePrivateKey(),
        tailgate::crypto::X25519PublicFromPrivate(tailgate::crypto::GeneratePrivateKey()));
    tailgate::types::netmap::PeerConfig missingPrefix = MakeDiscoPeer(
        tailgate::crypto::X25519PublicFromPrivate(tailgate::crypto::GeneratePrivateKey()),
        sender.PublicKey());
    missingPrefix.Key("machinekey:00");
    tailgate::types::netmap::PeerConfig shortDiscoKey = MakeDiscoPeer(
        tailgate::crypto::X25519PublicFromPrivate(tailgate::crypto::GeneratePrivateKey()),
        sender.PublicKey());
    shortDiscoKey.DiscoKey("discokey:0011");
    const std::vector<tailgate::types::netmap::PeerConfig> peers{missingPrefix, shortDiscoKey};

    const std::vector<tailgate::hosted::PeerPacket> probes =
        tailgate::hosted::BuildDiscoProbes(sender, peers, {});

    EXPECT_TRUE(probes.empty());
}

TEST(Given_HostedDiscoProbes,
     When_PeerAndServerHaveEndpoints_Then_UdpPathIsOpenedBeforeCandidateAdvertisement)
{
    constexpr std::uint16_t PeerPort = 41641;
    constexpr std::uint16_t ServerPort = 51234;
    const tailgate::crypto::Bytes32 senderNodePrivate = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 peerNodePrivate = tailgate::crypto::GeneratePrivateKey();
    const tailgate::disco::Disco sender(
        tailgate::crypto::GeneratePrivateKey(),
        tailgate::crypto::X25519PublicFromPrivate(senderNodePrivate));
    const tailgate::disco::Disco receiver(
        tailgate::crypto::GeneratePrivateKey(),
        tailgate::crypto::X25519PublicFromPrivate(peerNodePrivate));
    const tailgate::crypto::Bytes32 peerNodePublic =
        tailgate::crypto::X25519PublicFromPrivate(peerNodePrivate);
    tailgate::types::netmap::PeerConfig peer = MakeDiscoPeer(peerNodePublic, receiver.PublicKey());
    peer.Endpoints({"192.0.2.10:41641", "not-an-endpoint"});
    const std::vector<tailgate::types::netmap::PeerConfig> peers{peer};
    const tailgate::net::Endpoint serverEndpoint(
        tailgate::net::Ipv4Address::FromOctets(198, 51, 100, 20), ServerPort);

    const std::vector<tailgate::hosted::PeerPacket> probes =
        tailgate::hosted::BuildDiscoProbes(sender, peers, {serverEndpoint});
    const std::optional<tailgate::disco::Disco::Message> directPing =
        probes.size() > 1 ? receiver.Parse(probes[1].Payload()) : std::nullopt;
    const std::optional<tailgate::disco::Disco::Message> callMeMaybe =
        probes.size() > 2 ? receiver.Parse(probes[2].Payload()) : std::nullopt;

    EXPECT_EQ(probes.size(), 3U);
    EXPECT_EQ(probes.size() > 1 ? probes[1].EndpointAddress() : 0U,
              tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 10).HostOrder());
    EXPECT_EQ(probes.size() > 1 ? probes[1].EndpointPort() : 0U, PeerPort);
    EXPECT_TRUE(directPing.has_value());
    EXPECT_EQ(directPing ? directPing->Type : tailgate::disco::Disco::MessageType::Pong,
              tailgate::disco::Disco::MessageType::Ping);
    EXPECT_TRUE(callMeMaybe.has_value());
    EXPECT_EQ(callMeMaybe ? callMeMaybe->Type : tailgate::disco::Disco::MessageType::Pong,
              tailgate::disco::Disco::MessageType::CallMeMaybe);
    EXPECT_EQ(callMeMaybe ? callMeMaybe->Endpoints : std::vector<tailgate::net::Endpoint>{},
              (std::vector<tailgate::net::Endpoint>{serverEndpoint}));
}

TEST(Given_HostedDiscoProbes, When_PeerHasNoUsableEndpoint_Then_ServerCandidatesAreNotAdvertised)
{
    const tailgate::crypto::Bytes32 senderNodePrivate = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 peerNodePrivate = tailgate::crypto::GeneratePrivateKey();
    const tailgate::disco::Disco sender(
        tailgate::crypto::GeneratePrivateKey(),
        tailgate::crypto::X25519PublicFromPrivate(senderNodePrivate));
    const tailgate::disco::Disco receiver(
        tailgate::crypto::GeneratePrivateKey(),
        tailgate::crypto::X25519PublicFromPrivate(peerNodePrivate));
    tailgate::types::netmap::PeerConfig peer = MakeDiscoPeer(
        tailgate::crypto::X25519PublicFromPrivate(peerNodePrivate), receiver.PublicKey());
    peer.Endpoints({"not-an-endpoint"});
    const tailgate::net::Endpoint serverEndpoint(
        tailgate::net::Ipv4Address::FromOctets(198, 51, 100, 20), 51234);

    const std::vector<tailgate::hosted::PeerPacket> probes =
        tailgate::hosted::BuildDiscoEndpointProbes(sender, peer, {serverEndpoint});

    EXPECT_TRUE(probes.empty());
}
