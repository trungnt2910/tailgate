#include <algorithm>

#include <gtest/gtest.h>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/wgengine/wireguard/Router.h>

namespace
{

tailgate::types::netmap::PeerConfig Peer(const tailgate::crypto::Bytes32& privateKey,
                                         const std::string& address,
                                         const std::string& name = {})
{
    const auto publicKey = tailgate::crypto::X25519PublicFromPrivate(privateKey);
    tailgate::types::netmap::PeerConfig result;
    result.Address = address;
    result.Name = name;
    result.Addresses = {address};
    result.Key = "nodekey:" + tailgate::crypto::BytesToHex(publicKey.data(), publicKey.size());
    result.AllowedPrefixes = {tailgate::net::packet::Ipv4Prefix{
        .Network = *tailgate::net::packet::ParseIpv4(address), .PrefixLength = 32}};
    return result;
}

TEST(Given_HostedExitNode, When_RoutingPublicTraffic_Then_UsesSelectedExitNode)
{
    tailgate::crypto::Bytes32 privateKey{};
    privateKey[1] = 1;
    tailgate::crypto::Bytes32 regularPrivateKey{};
    regularPrivateKey[1] = 2;
    tailgate::crypto::Bytes32 exitPrivateKey{};
    exitPrivateKey[1] = 3;
    tailgate::types::netmap::PeerConfig regular = Peer(regularPrivateKey, "100.64.0.2", "regular");
    tailgate::types::netmap::PeerConfig exit = Peer(exitPrivateKey, "100.64.0.3", "exit");
    exit.ExitNodeOption = true;
    exit.Online = true;
    tailgate::wgengine::wireguard::WireGuardRouter router(privateKey, {regular, exit}, "exit");
    const std::vector<std::uint8_t> packet =
        tailgate::net::packet::BuildIpv4Packet(*tailgate::net::packet::ParseIpv4("100.64.0.1"),
                                               *tailgate::net::packet::ParseIpv4("203.0.113.10"),
                                               1,
                                               {1});
    const tailgate::crypto::Bytes32 exitPublic =
        tailgate::crypto::X25519PublicFromPrivate(exitPrivateKey);

    const auto outbound = router.Send(packet);
    ASSERT_EQ(outbound.size(), 1U);

    EXPECT_EQ(outbound.front().Peer, exitPublic);
}

} // namespace

TEST(Given_HostedPacket, When_Routed_Then_RelayOnlySeesWireGuardCiphertext)
{
    tailgate::crypto::Bytes32 firstPrivate{};
    firstPrivate[1] = 1;
    tailgate::crypto::Bytes32 secondPrivate{};
    secondPrivate[1] = 2;
    tailgate::wgengine::wireguard::WireGuardRouter first(firstPrivate,
                                                         {Peer(secondPrivate, "100.64.0.2")});
    tailgate::wgengine::wireguard::WireGuardRouter second(secondPrivate,
                                                          {Peer(firstPrivate, "100.64.0.1")});
    const std::vector<std::uint8_t> plaintext =
        tailgate::net::packet::BuildIpv4Packet(*tailgate::net::packet::ParseIpv4("100.64.0.1"),
                                               *tailgate::net::packet::ParseIpv4("100.64.0.2"),
                                               1,
                                               {1, 2, 3, 4});
    const auto firstPublic = tailgate::crypto::X25519PublicFromPrivate(firstPrivate);
    const auto secondPublic = tailgate::crypto::X25519PublicFromPrivate(secondPrivate);

    const auto initiation = first.Send(plaintext);
    ASSERT_EQ(initiation.size(), 1U);
    const auto response = second.Receive(firstPublic, initiation[0].Payload);
    ASSERT_EQ(response.Outbound.size(), 1U);
    const auto encrypted = first.Receive(secondPublic, response.Outbound[0].Payload);
    ASSERT_EQ(encrypted.Outbound.size(), 2U);
    const auto confirmation = second.Receive(firstPublic, encrypted.Outbound[0].Payload);
    const auto received = second.Receive(firstPublic, encrypted.Outbound[1].Payload);

    EXPECT_EQ(initiation.size(), 1U);
    EXPECT_EQ(response.Outbound.size(), 1U);
    EXPECT_EQ(encrypted.Outbound.size(), 2U);
    EXPECT_TRUE(confirmation.Plaintext.empty());
    EXPECT_TRUE(std::search(encrypted.Outbound[1].Payload.begin(),
                            encrypted.Outbound[1].Payload.end(),
                            plaintext.begin(),
                            plaintext.end()) == encrypted.Outbound[1].Payload.end());
    EXPECT_EQ(1U, received.Plaintext.size());
    EXPECT_EQ(plaintext, received.Plaintext[0]);
}

TEST(Given_UnknownWireGuardTransportSource, When_Received_Then_ItIsRejected)
{
    tailgate::crypto::Bytes32 privateKey{};
    privateKey[1] = 1;
    tailgate::crypto::Bytes32 peerPrivateKey{};
    peerPrivateKey[1] = 2;
    tailgate::crypto::Bytes32 unknownKey{};
    unknownKey[1] = 3;
    tailgate::wgengine::wireguard::WireGuardRouter router(privateKey,
                                                          {Peer(peerPrivateKey, "100.64.0.2")});

    const auto received = router.Receive(unknownKey, {1, 0, 0, 0});

    EXPECT_TRUE(received.Outbound.empty());
    EXPECT_TRUE(received.Plaintext.empty());
}
