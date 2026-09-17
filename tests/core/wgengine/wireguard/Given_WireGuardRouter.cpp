#include <algorithm>
#include <chrono>
#include <thread>

#include <gtest/gtest.h>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/net/Ipv4Address.h>
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
    result.Address(address);
    result.Name(name);
    result.Addresses({address});
    result.Key("nodekey:" + tailgate::crypto::BytesToHex(publicKey.data(), publicKey.size()));
    result.AllowedPrefixes({tailgate::net::packet::Ipv4Prefix(
        tailgate::net::Ipv4Address::Parse(address).HostOrder(), 32)});
    return result;
}

TEST(Given_WireGuardRouter, When_PeersHaveNoRequestedTraffic_Then_MaintenanceDoesNotInitiate)
{
    tailgate::crypto::Bytes32 privateKey{};
    privateKey[1] = 1;
    tailgate::crypto::Bytes32 peerPrivate{};
    peerPrivate[1] = 2;
    tailgate::wgengine::wireguard::WireGuardRouter router(privateKey,
                                                          {Peer(peerPrivate, "192.0.2.2")});

    const auto outbound = router.UpdateTimers();

    EXPECT_TRUE(outbound.empty());
}

TEST(Given_WireGuardRouter, When_OnePeerIsStarted_Then_OtherPeersRemainIdle)
{
    tailgate::crypto::Bytes32 privateKey{};
    privateKey[1] = 1;
    tailgate::crypto::Bytes32 requestedPrivate{};
    requestedPrivate[1] = 2;
    tailgate::crypto::Bytes32 unusedPrivate{};
    unusedPrivate[1] = 3;
    const auto requestedPublic = tailgate::crypto::X25519PublicFromPrivate(requestedPrivate);
    tailgate::wgengine::wireguard::WireGuardRouter router(
        privateKey, {Peer(requestedPrivate, "192.0.2.2"), Peer(unusedPrivate, "192.0.2.3")});

    const auto started = router.Start(requestedPublic);
    const auto duplicate = router.Start(requestedPublic);
    const auto maintenance = router.UpdateTimers();
    const bool requestedHandshake =
        started.size() == 1 && started.front().Peer == requestedPublic && started.front().Handshake;

    EXPECT_TRUE(requestedHandshake);
    EXPECT_TRUE(duplicate.empty());
    EXPECT_TRUE(maintenance.empty());
}

TEST(Given_WireGuardRouter, When_PeerIsAddedToLiveMap_Then_ItWaitsForRequestedTraffic)
{
    tailgate::crypto::Bytes32 privateKey{};
    privateKey[1] = 1;
    tailgate::crypto::Bytes32 peerPrivate{};
    peerPrivate[1] = 2;
    tailgate::wgengine::wireguard::WireGuardRouter router(privateKey, {});

    router.UpdatePeers({Peer(peerPrivate, "192.0.2.2")});
    const auto outbound = router.UpdateTimers();

    EXPECT_TRUE(outbound.empty());
}

TEST(Given_WireGuardRouter, When_RequestedHandshakeIsUnanswered_Then_MaintenanceRetries)
{
    tailgate::crypto::Bytes32 privateKey{};
    privateKey[1] = 1;
    tailgate::crypto::Bytes32 peerPrivate{};
    peerPrivate[1] = 2;
    const auto peerPublic = tailgate::crypto::X25519PublicFromPrivate(peerPrivate);
    tailgate::wgengine::wireguard::WireGuardRouter router(privateKey,
                                                          {Peer(peerPrivate, "192.0.2.2")});
    ASSERT_EQ(router.Start(peerPublic).size(), 1U);
    // The WireGuard backend uses a monotonic platform clock and a five-second retry timeout.
    constexpr auto RetryObservationDelay = std::chrono::seconds(6);

    std::this_thread::sleep_for(RetryObservationDelay);
    const auto retried = router.UpdateTimers();
    const bool retryForRequestedPeer = retried.size() == 1 && retried.front().Peer == peerPublic &&
                                       !retried.front().Payload.empty();

    EXPECT_TRUE(retryForRequestedPeer);
}

TEST(Given_WireGuardRouter, When_TransportSourceIsNotProvided_Then_PeerIsIdentifiedFromHandshake)
{
    tailgate::crypto::Bytes32 firstPrivate{};
    firstPrivate[1] = 1;
    tailgate::crypto::Bytes32 secondPrivate{};
    secondPrivate[1] = 2;
    const tailgate::crypto::Bytes32 firstPublic =
        tailgate::crypto::X25519PublicFromPrivate(firstPrivate);
    tailgate::wgengine::wireguard::WireGuardRouter first(firstPrivate,
                                                         {Peer(secondPrivate, "192.0.2.2")});
    tailgate::wgengine::wireguard::WireGuardRouter second(secondPrivate,
                                                          {Peer(firstPrivate, "192.0.2.1")});
    const std::vector<std::uint8_t> plaintext = tailgate::net::packet::Ipv4Packet::Build(
        tailgate::net::Ipv4Address::Parse("192.0.2.1").HostOrder(),
        tailgate::net::Ipv4Address::Parse("192.0.2.2").HostOrder(),
        1,
        {1});
    const auto initiation = first.Send(plaintext);
    ASSERT_EQ(initiation.size(), 1U);

    const tailgate::wgengine::wireguard::WireGuardRouter::ReceiveResult received =
        second.Receive(initiation.front().Payload);

    EXPECT_EQ(received.Source, firstPublic);
    EXPECT_EQ(received.Outbound.size(), 1U);
}

TEST(Given_WireGuardRouter, When_RoutingPublicTraffic_Then_SelectedExitNodeIsUsed)
{
    tailgate::crypto::Bytes32 privateKey{};
    privateKey[1] = 1;
    tailgate::crypto::Bytes32 regularPrivateKey{};
    regularPrivateKey[1] = 2;
    tailgate::crypto::Bytes32 exitPrivateKey{};
    exitPrivateKey[1] = 3;
    tailgate::types::netmap::PeerConfig regular = Peer(regularPrivateKey, "100.64.0.2", "regular");
    tailgate::types::netmap::PeerConfig exit = Peer(exitPrivateKey, "100.64.0.3", "exit");
    exit.ExitNodeOption(true);
    exit.Online(true);
    tailgate::wgengine::wireguard::WireGuardRouter router(privateKey, {regular, exit}, "exit");
    const std::vector<std::uint8_t> packet = tailgate::net::packet::Ipv4Packet::Build(
        tailgate::net::Ipv4Address::Parse("100.64.0.1").HostOrder(),
        tailgate::net::Ipv4Address::Parse("203.0.113.10").HostOrder(),
        1,
        {1});
    const tailgate::crypto::Bytes32 exitPublic =
        tailgate::crypto::X25519PublicFromPrivate(exitPrivateKey);

    const auto outbound = router.Send(packet);
    ASSERT_EQ(outbound.size(), 1U);

    EXPECT_EQ(outbound.front().Peer, exitPublic);
}

TEST(Given_WireGuardRouter, When_RoutingHostedPacket_Then_RelayOnlySeesCiphertext)
{
    tailgate::crypto::Bytes32 firstPrivate{};
    firstPrivate[1] = 1;
    tailgate::crypto::Bytes32 secondPrivate{};
    secondPrivate[1] = 2;
    tailgate::wgengine::wireguard::WireGuardRouter first(firstPrivate,
                                                         {Peer(secondPrivate, "100.64.0.2")});
    tailgate::wgengine::wireguard::WireGuardRouter second(secondPrivate,
                                                          {Peer(firstPrivate, "100.64.0.1")});
    const std::vector<std::uint8_t> plaintext = tailgate::net::packet::Ipv4Packet::Build(
        tailgate::net::Ipv4Address::Parse("100.64.0.1").HostOrder(),
        tailgate::net::Ipv4Address::Parse("100.64.0.2").HostOrder(),
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

TEST(Given_WireGuardRouter, When_TransportSourceIsUnknown_Then_PacketIsRejected)
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

} // namespace
