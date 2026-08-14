#include <gtest/gtest.h>

#include <tailgate/control/NetworkMap.h>
#include <tailgate/protocol/Crypto.h>
#include <tailgate/protocol/Disco.h>
#include <tailgate/relay/RelayProtocol.h>

namespace
{

tailgate::control::PeerConfig MakeDiscoPeer(const tailgate::protocol::Bytes32& nodePublicKey,
                                            const tailgate::protocol::Bytes32& discoPublicKey)
{
    tailgate::control::PeerConfig peer;
    peer.Key =
        "nodekey:" + tailgate::protocol::BytesToHex(nodePublicKey.data(), nodePublicKey.size());
    peer.DiscoKey =
        "discokey:" + tailgate::protocol::BytesToHex(discoPublicKey.data(), discoPublicKey.size());
    peer.Online = true;
    return peer;
}

} // namespace

TEST(Given_OnlineDiscoPeer, When_BuildingDiscoProbes_Then_PingTargetsThatPeer)
{
    const auto senderNode = tailgate::protocol::GeneratePrivateKey();
    const auto peerNode = tailgate::protocol::GeneratePrivateKey();
    const tailgate::protocol::Disco sender(tailgate::protocol::GeneratePrivateKey(),
                                           tailgate::protocol::X25519PublicFromPrivate(senderNode));
    const tailgate::protocol::Disco receiver(tailgate::protocol::GeneratePrivateKey(),
                                             tailgate::protocol::X25519PublicFromPrivate(peerNode));
    const tailgate::protocol::Bytes32 peerNodePublic =
        tailgate::protocol::X25519PublicFromPrivate(peerNode);
    const std::vector<tailgate::control::PeerConfig> peers{
        MakeDiscoPeer(peerNodePublic, receiver.PublicKey())};

    const std::vector<tailgate::relay::PeerPacket> probes =
        tailgate::relay::BuildDiscoProbes(sender, peers);
    const std::optional<tailgate::protocol::Disco::Message> message =
        probes.empty() ? std::nullopt : receiver.Parse(probes.front().Payload);
    const bool targetsPeer = !probes.empty() && probes.front().Peer == peerNodePublic;
    const bool isDisco = !probes.empty() && probes.front().Disco;
    const bool isPing =
        message.has_value() && message->Type == tailgate::protocol::Disco::MessageType::Ping;
    const bool identifiesSender = message.has_value() && message->Sender == sender.PublicKey();

    EXPECT_EQ(probes.size(), 1U);
    EXPECT_TRUE(message.has_value());
    EXPECT_TRUE(targetsPeer);
    EXPECT_TRUE(isDisco);
    EXPECT_TRUE(isPing);
    EXPECT_TRUE(identifiesSender);
}

TEST(Given_OfflineDiscoPeer, When_BuildingDiscoProbes_Then_NoPingIsBuilt)
{
    const tailgate::protocol::Disco sender(
        tailgate::protocol::GeneratePrivateKey(),
        tailgate::protocol::X25519PublicFromPrivate(tailgate::protocol::GeneratePrivateKey()));
    tailgate::control::PeerConfig peer = MakeDiscoPeer(
        tailgate::protocol::X25519PublicFromPrivate(tailgate::protocol::GeneratePrivateKey()),
        sender.PublicKey());
    peer.Online = false;
    const std::vector<tailgate::control::PeerConfig> peers{peer};

    const std::vector<tailgate::relay::PeerPacket> probes =
        tailgate::relay::BuildDiscoProbes(sender, peers);

    EXPECT_TRUE(probes.empty());
}

TEST(Given_PeerWithMalformedKeys, When_BuildingDiscoProbes_Then_NoPingIsBuilt)
{
    const tailgate::protocol::Disco sender(
        tailgate::protocol::GeneratePrivateKey(),
        tailgate::protocol::X25519PublicFromPrivate(tailgate::protocol::GeneratePrivateKey()));
    tailgate::control::PeerConfig missingPrefix = MakeDiscoPeer(
        tailgate::protocol::X25519PublicFromPrivate(tailgate::protocol::GeneratePrivateKey()),
        sender.PublicKey());
    missingPrefix.Key = "machinekey:00";
    tailgate::control::PeerConfig shortDiscoKey = MakeDiscoPeer(
        tailgate::protocol::X25519PublicFromPrivate(tailgate::protocol::GeneratePrivateKey()),
        sender.PublicKey());
    shortDiscoKey.DiscoKey = "discokey:0011";
    const std::vector<tailgate::control::PeerConfig> peers{missingPrefix, shortDiscoKey};

    const std::vector<tailgate::relay::PeerPacket> probes =
        tailgate::relay::BuildDiscoProbes(sender, peers);

    EXPECT_TRUE(probes.empty());
}
