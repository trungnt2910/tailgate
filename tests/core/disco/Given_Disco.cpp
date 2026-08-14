#include <gtest/gtest.h>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/disco/Disco.h>

TEST(Given_DiscoPeers, When_Pinging_Then_TheTransactionRoundTrips)
{
    const auto nodeA = tailgate::crypto::GeneratePrivateKey();
    const auto nodeB = tailgate::crypto::GeneratePrivateKey();
    tailgate::disco::Disco a(tailgate::crypto::GeneratePrivateKey(),
                             tailgate::crypto::X25519PublicFromPrivate(nodeA));
    tailgate::disco::Disco b(tailgate::crypto::GeneratePrivateKey(),
                             tailgate::crypto::X25519PublicFromPrivate(nodeB));

    const auto transaction = a.NewTransactionId();
    const auto ping = a.BuildPing(b.PublicKey(), transaction);
    const auto receivedPing = b.Parse(ping);
    const auto pong = b.BuildPong(a.PublicKey(), transaction, 0x01020304U, 1234);
    const auto receivedPong = a.Parse(pong);
    const bool pingTypeMatches =
        receivedPing.has_value() && receivedPing->Type == tailgate::disco::Disco::MessageType::Ping;
    const bool pingTransactionMatches =
        receivedPing.has_value() && receivedPing->Transaction == transaction;
    const bool pongTypeMatches =
        receivedPong.has_value() && receivedPong->Type == tailgate::disco::Disco::MessageType::Pong;
    const bool pongTransactionMatches =
        receivedPong.has_value() && receivedPong->Transaction == transaction;

    EXPECT_TRUE(receivedPing.has_value());
    EXPECT_TRUE(pingTypeMatches);
    EXPECT_TRUE(pingTransactionMatches);
    EXPECT_TRUE(receivedPong.has_value());
    EXPECT_TRUE(pongTypeMatches);
    EXPECT_TRUE(pongTransactionMatches);
}

TEST(Given_DiscoPeers, When_AdvertisingEndpoints_Then_Ipv4CandidatesRoundTrip)
{
    const auto nodeA = tailgate::crypto::GeneratePrivateKey();
    const auto nodeB = tailgate::crypto::GeneratePrivateKey();
    tailgate::disco::Disco a(tailgate::crypto::GeneratePrivateKey(),
                             tailgate::crypto::X25519PublicFromPrivate(nodeA));
    tailgate::disco::Disco b(tailgate::crypto::GeneratePrivateKey(),
                             tailgate::crypto::X25519PublicFromPrivate(nodeB));
    const std::vector<tailgate::disco::Disco::Endpoint> endpoints{{0xc0a86402U, 41641}};

    const auto packet = a.BuildCallMeMaybe(b.PublicKey(), endpoints);
    const auto message = b.Parse(packet);
    const auto messageType =
        message.has_value() ? message->Type : tailgate::disco::Disco::MessageType::Ping;
    const std::size_t endpointCount = message.has_value() ? message->Endpoints.size() : 0U;
    const std::uint32_t address = endpointCount == 1U ? message->Endpoints[0].Address : 0U;
    const std::uint16_t port = endpointCount == 1U ? message->Endpoints[0].Port : 0U;

    EXPECT_TRUE(message.has_value());
    EXPECT_EQ(messageType, tailgate::disco::Disco::MessageType::CallMeMaybe);
    EXPECT_EQ(endpointCount, 1U);
    EXPECT_EQ(address, 0xc0a86402U);
    EXPECT_EQ(port, 41641);
}
