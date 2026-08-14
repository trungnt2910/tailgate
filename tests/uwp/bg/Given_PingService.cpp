#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/disco/Disco.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/packet/Ipv4.h>

#include "common/UwpAppServiceProtocol.h"

#include "service/PingService.h"

#include "fakes/bg/manager/FakeDataPlaneManager.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

constexpr std::uint32_t AppAddress = 0x64400001U;
constexpr std::uint16_t AppPort = 49152;
constexpr std::uint64_t RequestSequence = 42;

std::optional<app_service::PingResponse>
DecodeResponse(const std::vector<std::vector<std::uint8_t>>& packets)
{
    if (packets.size() != 1)
    {
        return std::nullopt;
    }
    const auto datagram = tailgate::net::packet::ParseIpv4UdpDatagram(packets.front());
    if (!datagram)
    {
        return std::nullopt;
    }
    const auto message = app_service::DecodeMessage(datagram->Payload);
    return message ? app_service::DecodePingResponse(*message) : std::nullopt;
}

class Given_PingService : public testing::Test
{
protected:
    void SetUp() override
    {
        m_dataPlane = std::make_shared<FakeDataPlaneManager>();
        auto injector = di::make_injector(di::bind<bg::manager::DataPlaneManager>.to(
            [this](const auto&) -> bg::manager::DataPlaneManager&
            {
                return *m_dataPlane;
            }));
        m_subject = injector.create<std::unique_ptr<bg::service::PingService>>();
    }

    std::shared_ptr<FakeDataPlaneManager> m_dataPlane;
    std::unique_ptr<bg::service::PingService> m_subject;
};

TEST_F(Given_PingService, When_PeerDoesNotExist_Then_TypedErrorIsReturned)
{
    tailgate::net::packet::Ipv4UdpDatagram datagram;
    datagram.Source = AppAddress;
    datagram.SourcePort = AppPort;
    const app_service::PingRequest request{
        .Sequence = RequestSequence,
        .Target = "missing.example.ts.net",
    };
    const tailgate::types::netmap::NetworkConfig config;
    std::vector<std::uint8_t> relayOutput;
    std::vector<std::vector<std::uint8_t>> appResponses;

    m_subject->Handle(datagram, request, config, nullptr, "DERP-1", relayOutput, appResponses);
    const auto response = DecodeResponse(appResponses);

    EXPECT_EQ(m_dataPlane->ServiceCount(), 1U);
    EXPECT_EQ(appResponses.size(), 1U);
    EXPECT_TRUE(relayOutput.empty());
    EXPECT_TRUE(response.has_value());
    EXPECT_EQ(response.value_or(app_service::PingResponse{}).Result,
              app_service::Status::NoMatchingPeer);
    EXPECT_EQ(response.value_or(app_service::PingResponse{}).Sequence, RequestSequence);
}

TEST_F(Given_PingService, When_PeerHasNoUsableDiscoState_Then_TypedErrorIsReturned)
{
    tailgate::net::packet::Ipv4UdpDatagram datagram;
    datagram.Source = AppAddress;
    datagram.SourcePort = AppPort;
    const app_service::PingRequest request{
        .Sequence = RequestSequence,
        .Target = "peer.example.ts.net",
    };
    tailgate::types::netmap::PeerConfig peer;
    peer.Name = "peer.example.ts.net";
    peer.Address = "100.64.0.2";
    tailgate::types::netmap::NetworkConfig config;
    config.Peers.push_back(peer);
    std::vector<std::uint8_t> relayOutput;
    std::vector<std::vector<std::uint8_t>> appResponses;

    m_subject->Handle(datagram, request, config, nullptr, "DERP-1", relayOutput, appResponses);
    const auto response = DecodeResponse(appResponses);

    ASSERT_TRUE(response.has_value());
    EXPECT_TRUE(relayOutput.empty());
    EXPECT_EQ(response->Result, app_service::Status::NoDiscoKey);
    EXPECT_EQ(response->Sequence, RequestSequence);
}

TEST_F(Given_PingService, When_PeerReturnsPong_Then_SuccessfulResponseIsFlushed)
{
    const tailgate::crypto::Bytes32 localNodeKey = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 remoteNodeKey = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 localDiscoPrivate = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 remoteDiscoPrivate = tailgate::crypto::GeneratePrivateKey();
    tailgate::disco::Disco localDisco(localDiscoPrivate, localNodeKey);
    tailgate::disco::Disco remoteDisco(remoteDiscoPrivate, remoteNodeKey);
    tailgate::net::packet::Ipv4UdpDatagram datagram;
    datagram.Source = AppAddress;
    datagram.SourcePort = AppPort;
    const app_service::PingRequest request{
        .Sequence = RequestSequence,
        .Target = "peer.example.ts.net",
    };
    tailgate::types::netmap::PeerConfig peer;
    peer.Name = "peer.example.ts.net";
    peer.Address = "100.64.0.2";
    peer.Key =
        "nodekey:" + tailgate::crypto::BytesToHex(remoteNodeKey.data(), remoteNodeKey.size());
    peer.DiscoKey = "discokey:" + tailgate::crypto::BytesToHex(remoteDisco.PublicKey().data(),
                                                               remoteDisco.PublicKey().size());
    tailgate::types::netmap::NetworkConfig config;
    config.Peers.push_back(peer);
    std::vector<std::uint8_t> relayOutput;
    std::vector<std::vector<std::uint8_t>> immediateResponses;
    m_subject->Handle(
        datagram, request, config, &localDisco, "DERP-1", relayOutput, immediateResponses);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(relayOutput);
    const auto frame = decoder.Next();
    ASSERT_TRUE(frame.has_value());
    const tailgate::hosted::PeerPacket sentPacket =
        tailgate::hosted::DecodePeerPacket(frame->Payload);
    const auto ping = remoteDisco.Parse(sentPacket.Payload);
    ASSERT_TRUE(ping.has_value());
    const tailgate::crypto::Bytes32 localDiscoPublic = localDisco.PublicKey();
    const std::vector<std::uint8_t> pongPayload =
        remoteDisco.BuildPong(localDiscoPublic, ping->Transaction, 0, 0);
    const auto pong = localDisco.Parse(pongPayload);
    ASSERT_TRUE(pong.has_value());
    tailgate::hosted::PeerPacket receivedPacket;
    receivedPacket.Peer = remoteNodeKey;
    receivedPacket.Payload = pongPayload;
    receivedPacket.Disco = true;
    std::vector<std::vector<std::uint8_t>> appResponses;

    m_subject->Complete(*pong, receivedPacket);
    m_subject->FlushLocal(appResponses);
    const auto response = DecodeResponse(appResponses);

    ASSERT_TRUE(response.has_value());
    EXPECT_TRUE(immediateResponses.empty());
    EXPECT_EQ(response->Result, app_service::Status::Ok);
    EXPECT_EQ(response->Sequence, RequestSequence);
    EXPECT_EQ(response->Relay, "DERP-1");
    EXPECT_FALSE(response->Direct);
}

} // namespace
} // namespace tailgate::uwp::tests
