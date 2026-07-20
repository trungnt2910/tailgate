#include <gtest/gtest.h>

#include "tailgate/network/Ipv4.h"
#include "tailgate/protocol/Crypto.h"
#include "tailgate/protocol/WireGuardRouter.h"

#include <algorithm>

namespace
{

tailgate::control::PeerConfig Peer(const tailgate::protocol::Bytes32& privateKey,
                                   const std::string& address,
                                   const std::string& name = {})
{
    const auto publicKey = tailgate::protocol::X25519PublicFromPrivate(privateKey);
    tailgate::control::PeerConfig result;
    result.Address = address;
    result.Name = name;
    result.Addresses = {address};
    result.Key = "nodekey:" + tailgate::protocol::BytesToHex(publicKey.data(), publicKey.size());
    result.AllowedPrefixes = {tailgate::network::Ipv4Prefix{
        .Network = *tailgate::network::ParseIpv4(address), .PrefixLength = 32}};
    return result;
}

TEST(Given_HostedExitNode, When_RoutingPublicTraffic_Then_UsesSelectedExitNode)
{
    tailgate::protocol::Bytes32 privateKey{};
    privateKey[1] = 1;
    tailgate::protocol::Bytes32 regularPrivateKey{};
    regularPrivateKey[1] = 2;
    tailgate::protocol::Bytes32 exitPrivateKey{};
    exitPrivateKey[1] = 3;
    tailgate::control::PeerConfig regular = Peer(regularPrivateKey, "100.64.0.2", "regular");
    tailgate::control::PeerConfig exit = Peer(exitPrivateKey, "100.64.0.3", "exit");
    exit.ExitNodeOption = true;
    exit.Online = true;
    tailgate::protocol::WireGuardRouter router(privateKey, {regular, exit}, "exit");
    const std::vector<std::uint8_t> packet =
        tailgate::network::BuildIpv4Packet(*tailgate::network::ParseIpv4("100.64.0.1"),
                                           *tailgate::network::ParseIpv4("8.8.8.8"),
                                           1,
                                           {1});
    const tailgate::protocol::Bytes32 exitPublic =
        tailgate::protocol::X25519PublicFromPrivate(exitPrivateKey);

    const auto outbound = router.Send(packet);

    EXPECT_EQ(outbound.size(), 1U);
    EXPECT_EQ(outbound.front().Peer, exitPublic);
}

} // namespace

TEST(Given_HostedPacket, When_Routed_Then_RelayOnlySeesWireGuardCiphertext)
{
    tailgate::protocol::Bytes32 firstPrivate{};
    firstPrivate[1] = 1;
    tailgate::protocol::Bytes32 secondPrivate{};
    secondPrivate[1] = 2;
    tailgate::protocol::WireGuardRouter first(firstPrivate, {Peer(secondPrivate, "100.64.0.2")});
    tailgate::protocol::WireGuardRouter second(secondPrivate, {Peer(firstPrivate, "100.64.0.1")});
    const std::vector<std::uint8_t> plaintext =
        tailgate::network::BuildIpv4Packet(*tailgate::network::ParseIpv4("100.64.0.1"),
                                           *tailgate::network::ParseIpv4("100.64.0.2"),
                                           1,
                                           {1, 2, 3, 4});
    const auto firstPublic = tailgate::protocol::X25519PublicFromPrivate(firstPrivate);
    const auto secondPublic = tailgate::protocol::X25519PublicFromPrivate(secondPrivate);

    const auto initiation = first.Send(plaintext);
    EXPECT_EQ(1U, initiation.size());
    const auto response = second.Receive(firstPublic, initiation[0].Payload);
    EXPECT_EQ(1U, response.Outbound.size());
    const auto encrypted = first.Receive(secondPublic, response.Outbound[0].Payload);
    EXPECT_EQ(2U, encrypted.Outbound.size());
    const auto confirmation = second.Receive(firstPublic, encrypted.Outbound[0].Payload);
    const auto received = second.Receive(firstPublic, encrypted.Outbound[1].Payload);

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
    tailgate::protocol::Bytes32 privateKey{};
    privateKey[1] = 1;
    tailgate::protocol::Bytes32 peerPrivateKey{};
    peerPrivateKey[1] = 2;
    tailgate::protocol::Bytes32 unknownKey{};
    unknownKey[1] = 3;
    tailgate::protocol::WireGuardRouter router(privateKey, {Peer(peerPrivateKey, "100.64.0.2")});

    const auto received = router.Receive(unknownKey, {1, 0, 0, 0});

    EXPECT_TRUE(received.Outbound.empty());
    EXPECT_TRUE(received.Plaintext.empty());
}
