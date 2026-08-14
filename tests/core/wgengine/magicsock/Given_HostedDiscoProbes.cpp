#include <gtest/gtest.h>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/disco/Disco.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace
{

tailgate::types::netmap::PeerConfig MakeDiscoPeer(const tailgate::crypto::Bytes32& nodePublicKey,
                                                  const tailgate::crypto::Bytes32& discoPublicKey)
{
    tailgate::types::netmap::PeerConfig peer;
    peer.Key =
        "nodekey:" + tailgate::crypto::BytesToHex(nodePublicKey.data(), nodePublicKey.size());
    peer.DiscoKey =
        "discokey:" + tailgate::crypto::BytesToHex(discoPublicKey.data(), discoPublicKey.size());
    peer.Online = true;
    return peer;
}

} // namespace

TEST(Given_OnlineDiscoPeer, When_BuildingDiscoProbes_Then_PingTargetsThatPeer)
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
        tailgate::hosted::BuildDiscoProbes(sender, peers);
    const std::optional<tailgate::disco::Disco::Message> message =
        probes.empty() ? std::nullopt : receiver.Parse(probes.front().Payload);
    const bool targetsPeer = !probes.empty() && probes.front().Peer == peerNodePublic;
    const bool isDisco = !probes.empty() && probes.front().Disco;
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

TEST(Given_OfflineDiscoPeer, When_BuildingDiscoProbes_Then_NoPingIsBuilt)
{
    const tailgate::disco::Disco sender(
        tailgate::crypto::GeneratePrivateKey(),
        tailgate::crypto::X25519PublicFromPrivate(tailgate::crypto::GeneratePrivateKey()));
    tailgate::types::netmap::PeerConfig peer = MakeDiscoPeer(
        tailgate::crypto::X25519PublicFromPrivate(tailgate::crypto::GeneratePrivateKey()),
        sender.PublicKey());
    peer.Online = false;
    const std::vector<tailgate::types::netmap::PeerConfig> peers{peer};

    const std::vector<tailgate::hosted::PeerPacket> probes =
        tailgate::hosted::BuildDiscoProbes(sender, peers);

    EXPECT_TRUE(probes.empty());
}

TEST(Given_PeerWithMalformedKeys, When_BuildingDiscoProbes_Then_NoPingIsBuilt)
{
    const tailgate::disco::Disco sender(
        tailgate::crypto::GeneratePrivateKey(),
        tailgate::crypto::X25519PublicFromPrivate(tailgate::crypto::GeneratePrivateKey()));
    tailgate::types::netmap::PeerConfig missingPrefix = MakeDiscoPeer(
        tailgate::crypto::X25519PublicFromPrivate(tailgate::crypto::GeneratePrivateKey()),
        sender.PublicKey());
    missingPrefix.Key = "machinekey:00";
    tailgate::types::netmap::PeerConfig shortDiscoKey = MakeDiscoPeer(
        tailgate::crypto::X25519PublicFromPrivate(tailgate::crypto::GeneratePrivateKey()),
        sender.PublicKey());
    shortDiscoKey.DiscoKey = "discokey:0011";
    const std::vector<tailgate::types::netmap::PeerConfig> peers{missingPrefix, shortDiscoKey};

    const std::vector<tailgate::hosted::PeerPacket> probes =
        tailgate::hosted::BuildDiscoProbes(sender, peers);

    EXPECT_TRUE(probes.empty());
}
