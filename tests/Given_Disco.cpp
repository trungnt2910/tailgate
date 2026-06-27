#include <gtest/gtest.h>

#include "tailgate/protocol/Crypto.h"
#include "tailgate/protocol/Disco.h"

TEST(Tailgate, GivenDiscoPeers_WhenPinging_ThenTheTransactionRoundTrips)
{
    const auto nodeA = tailgate::protocol::GeneratePrivateKey();
    const auto nodeB = tailgate::protocol::GeneratePrivateKey();
    tailgate::protocol::Disco a(tailgate::protocol::GeneratePrivateKey(),
                                tailgate::protocol::X25519PublicFromPrivate(nodeA));
    tailgate::protocol::Disco b(tailgate::protocol::GeneratePrivateKey(),
                                tailgate::protocol::X25519PublicFromPrivate(nodeB));

    const auto transaction = a.NewTransactionId();
    const auto ping = a.BuildPing(b.PublicKey(), transaction);
    const auto receivedPing = b.Parse(ping);

    ASSERT_TRUE(receivedPing.has_value());
    ASSERT_TRUE(receivedPing->Type == tailgate::protocol::Disco::MessageType::Ping);
    ASSERT_TRUE(receivedPing->Transaction == transaction);

    const auto pong = b.BuildPong(a.PublicKey(), transaction, 0x01020304U, 1234);
    const auto receivedPong = a.Parse(pong);

    ASSERT_TRUE(receivedPong.has_value());
    ASSERT_TRUE(receivedPong->Type == tailgate::protocol::Disco::MessageType::Pong);
    ASSERT_TRUE(receivedPong->Transaction == transaction);
}

TEST(Tailgate, GivenDiscoPeers_WhenAdvertisingEndpoints_ThenIpv4CandidatesRoundTrip)
{
    const auto nodeA = tailgate::protocol::GeneratePrivateKey();
    const auto nodeB = tailgate::protocol::GeneratePrivateKey();
    tailgate::protocol::Disco a(tailgate::protocol::GeneratePrivateKey(),
                                tailgate::protocol::X25519PublicFromPrivate(nodeA));
    tailgate::protocol::Disco b(tailgate::protocol::GeneratePrivateKey(),
                                tailgate::protocol::X25519PublicFromPrivate(nodeB));
    const std::vector<tailgate::protocol::Disco::Endpoint> endpoints{{0xc0a86402U, 41641}};

    const auto packet = a.BuildCallMeMaybe(b.PublicKey(), endpoints);
    const auto message = b.Parse(packet);

    ASSERT_TRUE(message.has_value());
    ASSERT_EQ(message->Type, tailgate::protocol::Disco::MessageType::CallMeMaybe);
    ASSERT_EQ(message->Endpoints.size(), 1U);
    ASSERT_EQ(message->Endpoints[0].Address, 0xc0a86402U);
    ASSERT_EQ(message->Endpoints[0].Port, 41641);
}
