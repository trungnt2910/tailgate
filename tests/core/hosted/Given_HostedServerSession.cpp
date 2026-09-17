#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/hosted/Pump.h>
#include <tailgate/hosted/ServerSession.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/netmap/NetworkMap.h>

#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/hosted/ActiveServerSession.h"

namespace tailgate::tests
{
namespace
{

class Given_HostedServerSession : public testing::Test
{
protected:
    fakes::ActiveServerSession m_active;
    fakes::FakeTimeProvider& m_clock =
        dynamic_cast<fakes::FakeTimeProvider&>(m_active.Injector.create<base::TimeProvider&>());
};

constexpr std::uint64_t NodeId = 42;
constexpr std::uint16_t DnsTransactionId = 0x1234;
constexpr std::uint16_t DnsSourcePort = 49152;
constexpr std::uint32_t ClientAddress =
    tailgate::net::Ipv4Address::FromOctets(100, 64, 0, 1).HostOrder();

using tailgate::tests::fakes::ActiveServerSession;

TEST_F(Given_HostedServerSession, When_ClientProofIsValid_Then_SessionIsAuthenticated)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& factory = injector.create<tailgate::hosted::ServerSessionFactory&>();
    const tailgate::crypto::Bytes32 clientPrivateKey = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 clientPublicKey =
        tailgate::crypto::X25519PublicFromPrivate(clientPrivateKey);
    const tailgate::crypto::Bytes32 relayPrivateKey = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 relayPublicKey =
        tailgate::crypto::X25519PublicFromPrivate(relayPrivateKey);
    auto subject = factory.CreateServerSession(tailgate::hosted::ServerSessionOptions{
        .ExpectedTailnet = "example.ts.net",
        .RelayHostName = "relay.example.ts.net",
        .RelayHostAddress = "100.64.0.10",
        .RelayPrivateKey = relayPrivateKey,
        .RelayPublicKey = relayPublicKey,
    });
    const tailgate::hosted::Challenge challenge =
        tailgate::hosted::ProtocolCodec::DecodeChallenge(subject->StartAuthentication().Payload());
    const tailgate::crypto::Bytes32 clientNonce = tailgate::crypto::GeneratePrivateKey();
    const tailgate::hosted::Authentication authentication(
        "example.ts.net",
        NodeId,
        "client.example.ts.net",
        "TestOS",
        "1",
        clientPublicKey,
        clientNonce,
        tailgate::hosted::CreateClientProof(
            clientPrivateKey, challenge.RelayPublicKey(), challenge.ServerNonce(), clientNonce));

    const tailgate::hosted::ServerAuthenticationResult evaluated =
        subject->EvaluateAuthentication(tailgate::hosted::Frame(
            tailgate::hosted::MessageType::Authenticate,
            tailgate::hosted::ProtocolCodec::EncodeAuthentication(authentication)));
    const tailgate::hosted::Frame result = subject->CompleteAuthentication(true);

    EXPECT_TRUE(evaluated.ProofValid);
    EXPECT_TRUE(evaluated.TailnetMatches);
    EXPECT_EQ(result.Type(), tailgate::hosted::MessageType::Authenticated);
}

TEST_F(Given_HostedServerSession, When_NetworkMapChangesIdentity_Then_TypedErrorIsReturned)
{
    ActiveServerSession active;
    tailgate::types::netmap::NetworkConfig changed = active.Network;
    changed.SelfNodeId(changed.SelfNodeId() + 1);
    const tailgate::hosted::Frame update(
        tailgate::hosted::MessageType::NetworkMap,
        tailgate::hosted::ProtocolCodec::EncodeNetworkConfig(changed));
    std::optional<tailgate::hosted::ServerSessionError> error;

    try
    {
        (void)active.Session->Process(update);
    }
    catch (const tailgate::hosted::ServerSessionException& exception)
    {
        error = exception.Error();
    }

    EXPECT_EQ(error, tailgate::hosted::ServerSessionError::NetworkMapIdentityChanged);
}

TEST_F(Given_HostedServerSession, When_ClientPacketArrives_Then_PayloadIsClassifiedForForwarding)
{
    ActiveServerSession active;
    const std::vector<std::uint8_t> payload{1, 2, 3, 4};
    const tailgate::hosted::Frame frame(tailgate::hosted::MessageType::ClientPacket, payload);

    const tailgate::hosted::ServerSessionProcessResult result = active.Session->Process(frame);

    ASSERT_TRUE(result.PeerPacketPayload.has_value());
    EXPECT_EQ(*result.PeerPacketPayload, payload);
}

TEST_F(Given_HostedServerSession, When_VerifiedPeerEndpointArrives_Then_UpdateIsForwarded)
{
    ActiveServerSession active;
    tailgate::crypto::Bytes32 peer{};
    peer[0] = 42;
    const tailgate::net::Endpoint endpoint(tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 10),
                                           41641);
    const tailgate::hosted::Frame frame(tailgate::hosted::MessageType::PeerEndpoint,
                                        tailgate::hosted::ProtocolCodec::EncodePeerEndpoint(
                                            tailgate::hosted::PeerEndpoint(peer, endpoint)));

    const tailgate::hosted::ServerSessionProcessResult result = active.Session->Process(frame);

    ASSERT_TRUE(result.VerifiedPeerEndpoint.has_value());
    EXPECT_EQ(result.VerifiedPeerEndpoint->Peer(), peer);
    EXPECT_EQ(result.VerifiedPeerEndpoint->Endpoint(), endpoint);
}

TEST_F(Given_HostedServerSession, When_TailnetDnsQueryArrives_Then_CoreBuildsResponse)
{
    ActiveServerSession active;
    tailgate::types::netmap::PeerConfig peer;
    peer.Name("peer.example.ts.net");
    peer.Address("100.64.0.2");
    peer.Addresses({peer.Address()});
    active.Network.Peers({std::move(peer)});
    (void)active.Session->Process(tailgate::hosted::Frame(
        tailgate::hosted::MessageType::NetworkMap,
        tailgate::hosted::ProtocolCodec::EncodeNetworkConfig(active.Network)));
    const std::vector<std::uint8_t> query =
        tailgate::net::dns::DnsQuery::Build("peer.example.ts.net", DnsTransactionId);
    const tailgate::hosted::Frame frame(
        tailgate::hosted::MessageType::TailnetDnsQuery,
        tailgate::net::packet::Ipv4UdpDatagram::Build(ClientAddress,
                                                      tailgate::net::dns::MagicDnsIpv4Address,
                                                      DnsSourcePort,
                                                      tailgate::net::dns::DnsPort,
                                                      query));

    const tailgate::hosted::ServerSessionProcessResult result = active.Session->Process(frame);

    ASSERT_EQ(result.RemoteOutput.size(), 1U);
    EXPECT_EQ(result.DnsName, "peer.example.ts.net");
    EXPECT_EQ(result.RemoteOutput.front().Type(),
              tailgate::hosted::MessageType::TailnetDnsResponse);
}

TEST_F(Given_HostedServerSession, When_DerpChallengesAreBuilt_Then_RequestIdsAreMonotonic)
{
    ActiveServerSession active;
    const tailgate::crypto::Bytes32 firstKey = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 secondKey = tailgate::crypto::GeneratePrivateKey();

    const tailgate::hosted::ServerDerpChallenge first =
        active.Session->BuildDerpChallenge(firstKey);
    const tailgate::hosted::ServerDerpChallenge second =
        active.Session->BuildDerpChallenge(secondKey);

    EXPECT_EQ(second.RequestId, first.RequestId + 1);
    EXPECT_EQ(first.Output.Type(), tailgate::hosted::MessageType::DerpChallenge);
    EXPECT_EQ(second.Output.Type(), tailgate::hosted::MessageType::DerpChallenge);
}

TEST_F(Given_HostedServerSession, When_ImmediateScheduleArrives_Then_ExactlyOneReplyIsReady)
{
    const auto request = hosted::EncodePumpSchedule(
        hosted::PumpSchedule{.RequestId = 1, .Delay = std::chrono::milliseconds::zero()});

    const auto processed = m_active.Session->Process(request);
    const auto reply = m_active.Session->TakeDuePump();
    const auto repeated = m_active.Session->TakeDuePump();
    const auto requestId = reply ? hosted::TryDecodePumpReply(reply->Payload()) : std::nullopt;

    EXPECT_TRUE(processed.PumpScheduleChanged);
    EXPECT_TRUE(processed.RemoteOutput.empty());
    EXPECT_EQ(requestId, 1U);
    EXPECT_FALSE(repeated.has_value());
    EXPECT_FALSE(m_active.Session->NextPumpDeadline().has_value());
}

TEST_F(Given_HostedServerSession, When_DeadlineHasNotPassed_Then_ReplyRemainsPending)
{
    const auto delay = std::chrono::milliseconds(100);
    (void)m_active.Session->Process(
        hosted::EncodePumpSchedule(hosted::PumpSchedule{.RequestId = 1, .Delay = delay}));

    m_clock.Advance(delay - std::chrono::milliseconds(1));
    const auto early = m_active.Session->TakeDuePump();
    m_clock.Advance(std::chrono::milliseconds(1));
    const auto due = m_active.Session->TakeDuePump();
    const auto requestId = due ? hosted::TryDecodePumpReply(due->Payload()) : std::nullopt;

    EXPECT_FALSE(early.has_value());
    EXPECT_EQ(requestId, 1U);
}

TEST_F(Given_HostedServerSession, When_NewerScheduleArrives_Then_ItReplacesTheDeadline)
{
    (void)m_active.Session->Process(hosted::EncodePumpSchedule(
        hosted::PumpSchedule{.RequestId = 1, .Delay = std::chrono::milliseconds(1)}));

    const auto processed = m_active.Session->Process(hosted::EncodePumpSchedule(
        hosted::PumpSchedule{.RequestId = 2, .Delay = std::chrono::milliseconds(100)}));
    m_clock.Advance(std::chrono::milliseconds(1));
    const auto oldDeadline = m_active.Session->TakeDuePump();
    m_clock.Advance(std::chrono::milliseconds(99));
    const auto due = m_active.Session->TakeDuePump();
    const auto requestId = due ? hosted::TryDecodePumpReply(due->Payload()) : std::nullopt;

    EXPECT_TRUE(processed.PumpScheduleChanged);
    EXPECT_FALSE(oldDeadline.has_value());
    EXPECT_EQ(requestId, 2U);
}

TEST_F(Given_HostedServerSession, When_CancelIsFollowedByStaleRequest_Then_NoReplyIsSent)
{
    const auto request = hosted::EncodePumpSchedule(
        hosted::PumpSchedule{.RequestId = 1, .Delay = std::chrono::milliseconds::zero()});
    (void)m_active.Session->Process(request);

    const auto cancelled = m_active.Session->Process(
        hosted::EncodePumpSchedule(hosted::PumpSchedule{.RequestId = 2, .Delay = std::nullopt}));
    const auto stale = m_active.Session->Process(request);
    const auto reply = m_active.Session->TakeDuePump();

    EXPECT_TRUE(cancelled.PumpScheduleChanged);
    EXPECT_FALSE(stale.PumpScheduleChanged);
    EXPECT_FALSE(reply.has_value());
    EXPECT_FALSE(m_active.Session->NextPumpDeadline().has_value());
}

TEST_F(Given_HostedServerSession, When_ImmediateRequestsRepeat_Then_RepliesAreRateLimited)
{
    (void)m_active.Session->Process(hosted::EncodePumpSchedule(
        hosted::PumpSchedule{.RequestId = 1, .Delay = std::chrono::milliseconds::zero()}));
    ASSERT_TRUE(m_active.Session->TakeDuePump().has_value());

    (void)m_active.Session->Process(hosted::EncodePumpSchedule(
        hosted::PumpSchedule{.RequestId = 2, .Delay = std::chrono::milliseconds::zero()}));
    const auto immediate = m_active.Session->TakeDuePump();
    m_clock.Advance(hosted::MinimumPumpInterval);
    const auto due = m_active.Session->TakeDuePump();
    const auto requestId = due ? hosted::TryDecodePumpReply(due->Payload()) : std::nullopt;

    EXPECT_FALSE(immediate.has_value());
    EXPECT_EQ(requestId, 2U);
}

TEST_F(Given_HostedServerSession, When_ScheduleIsMalformed_Then_ItCannotCreateWork)
{
    const hosted::Frame request(hosted::MessageType::PumpSchedule, {1, 2, 3});

    EXPECT_THROW((void)m_active.Session->Process(request), hosted::PumpException);
    EXPECT_FALSE(m_active.Session->NextPumpDeadline().has_value());
}

} // namespace
} // namespace tailgate::tests
