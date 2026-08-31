#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/hosted/ServerSession.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/netmap/NetworkMap.h>

#include "fakes/di/FakeNetworkBindings.h"

namespace
{

constexpr std::uint64_t NodeId = 42;
constexpr std::uint16_t DnsTransactionId = 0x1234;
constexpr std::uint16_t DnsSourcePort = 49152;
constexpr std::uint32_t ClientAddress =
    tailgate::net::Ipv4Address::FromOctets(100, 64, 0, 1).HostOrder();

struct ActiveServerSession
{
    tailgate::di::Injector Injector;
    tailgate::crypto::Bytes32 ClientPrivateKey = tailgate::crypto::GeneratePrivateKey();
    tailgate::crypto::Bytes32 ClientPublicKey =
        tailgate::crypto::X25519PublicFromPrivate(ClientPrivateKey);
    tailgate::crypto::Bytes32 RelayPrivateKey = tailgate::crypto::GeneratePrivateKey();
    tailgate::crypto::Bytes32 RelayPublicKey =
        tailgate::crypto::X25519PublicFromPrivate(RelayPrivateKey);
    std::unique_ptr<tailgate::hosted::ServerSession> Session;
    tailgate::types::netmap::NetworkConfig Network;

    ActiveServerSession()
    {
        tailgate::tests::fakes::InstallFakeNetworkBindings(Injector);
        auto& factory = Injector.create<tailgate::hosted::ServerSessionFactory&>();
        Session = factory.CreateServerSession(tailgate::hosted::ServerSessionOptions{
            .ExpectedTailnet = "example.ts.net",
            .RelayHostName = "relay.example.ts.net",
            .RelayHostAddress = "100.64.0.10",
            .RelayPrivateKey = RelayPrivateKey,
            .RelayPublicKey = RelayPublicKey,
        });
        const tailgate::hosted::Challenge challenge =
            tailgate::hosted::ProtocolCodec::DecodeChallenge(
                Session->StartAuthentication().Payload());
        const tailgate::crypto::Bytes32 clientNonce = tailgate::crypto::GeneratePrivateKey();
        const tailgate::hosted::Authentication authentication(
            "example.ts.net",
            NodeId,
            "client.example.ts.net",
            "TestOS",
            "1",
            ClientPublicKey,
            clientNonce,
            tailgate::hosted::CreateClientProof(ClientPrivateKey,
                                                challenge.RelayPublicKey(),
                                                challenge.ServerNonce(),
                                                clientNonce));
        (void)Session->EvaluateAuthentication(tailgate::hosted::Frame(
            tailgate::hosted::MessageType::Authenticate,
            tailgate::hosted::ProtocolCodec::EncodeAuthentication(authentication)));
        (void)Session->CompleteAuthentication(true);
        Network.Domain("example.ts.net");
        Network.SelfNodeId(NodeId);
        Network.SelfKey("nodekey:" + tailgate::crypto::BytesToHex(ClientPublicKey.data(),
                                                                  ClientPublicKey.size()));
        Network.SelfAddress("100.64.0.1");
        Network.SelfName("client.example.ts.net");
        Network.MagicDnsDomain("example.ts.net");
        (void)Session->AcceptInitialNetworkMap(
            tailgate::hosted::Frame(tailgate::hosted::MessageType::NetworkMap,
                                    tailgate::hosted::ProtocolCodec::EncodeNetworkConfig(Network)));
    }
};

TEST(Given_HostedServerSession, When_ClientProofIsValid_Then_SessionIsAuthenticated)
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

TEST(Given_HostedServerSession, When_NetworkMapChangesIdentity_Then_TypedErrorIsReturned)
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

TEST(Given_HostedServerSession, When_ClientPacketArrives_Then_PayloadIsClassifiedForForwarding)
{
    ActiveServerSession active;
    const std::vector<std::uint8_t> payload{1, 2, 3, 4};
    const tailgate::hosted::Frame frame(tailgate::hosted::MessageType::ClientPacket, payload);

    const tailgate::hosted::ServerSessionProcessResult result = active.Session->Process(frame);

    ASSERT_TRUE(result.PeerPacketPayload.has_value());
    EXPECT_EQ(*result.PeerPacketPayload, payload);
}

TEST(Given_HostedServerSession, When_VerifiedPeerEndpointArrives_Then_UpdateIsForwarded)
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

TEST(Given_HostedServerSession, When_TailnetDnsQueryArrives_Then_CoreBuildsResponse)
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

TEST(Given_HostedServerSession, When_DerpChallengesAreBuilt_Then_RequestIdsAreMonotonic)
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

} // namespace
