#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>

#include "service/HostedDnsService.h"

#include "fakes/bg/manager/FakeDataPlaneManager.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

constexpr std::uint32_t SelfAddress = 0x64400001U;
constexpr std::uint32_t OtherAddress = 0x64400002U;
constexpr std::uint16_t SourcePort = 49152;
constexpr std::uint16_t TransactionId = 0x1234;

class Given_HostedDnsService : public testing::Test
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
        m_subject = injector.create<std::unique_ptr<bg::service::HostedDnsService>>();
    }

    std::shared_ptr<FakeDataPlaneManager> m_dataPlane;
    std::unique_ptr<bg::service::HostedDnsService> m_subject;
};

TEST_F(Given_HostedDnsService, When_EncapsulatingMagicDnsQuery_Then_RelayFrameIsProduced)
{
    tailgate::types::netmap::NetworkConfig config;
    config.SelfAddress = "100.64.0.1";
    const std::vector<std::uint8_t> query =
        tailgate::net::dns::BuildDnsQuery("host.example.ts.net", TransactionId);
    const std::vector<std::uint8_t> packet =
        tailgate::net::packet::BuildUdpPacket(SelfAddress,
                                              tailgate::net::dns::MagicDnsIpv4Address,
                                              SourcePort,
                                              tailgate::net::dns::DnsPort,
                                              query);
    const std::string exitNode;
    const std::string relayName;
    std::vector<std::uint8_t> remoteOutput;
    bg::service::EncapsulationContext context{
        .Original = packet,
        .Config = config,
        .ExitNode = exitNode,
        .RelayName = relayName,
        .RemoteOutput = remoteOutput,
    };

    m_subject->Encapsulate(context);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(remoteOutput);
    const std::optional<tailgate::hosted::Frame> frame = decoder.Next();

    EXPECT_EQ(m_dataPlane->ServiceCount(), 1U);
    EXPECT_TRUE(frame.has_value());
    EXPECT_EQ(frame.value_or(tailgate::hosted::Frame{}).Type,
              tailgate::hosted::MessageType::TailnetDnsQuery);
    EXPECT_EQ(frame.value_or(tailgate::hosted::Frame{}).Payload, packet);
}

TEST_F(Given_HostedDnsService, When_QuerySourceDoesNotMatchSelf_Then_QueryIsDropped)
{
    tailgate::types::netmap::NetworkConfig config;
    config.SelfAddress = "100.64.0.1";
    const std::vector<std::uint8_t> query =
        tailgate::net::dns::BuildDnsQuery("host.example.ts.net", TransactionId);
    const std::vector<std::uint8_t> packet =
        tailgate::net::packet::BuildUdpPacket(OtherAddress,
                                              tailgate::net::dns::MagicDnsIpv4Address,
                                              SourcePort,
                                              tailgate::net::dns::DnsPort,
                                              query);
    const std::string exitNode;
    const std::string relayName;
    std::vector<std::uint8_t> remoteOutput;
    bg::service::EncapsulationContext context{
        .Original = packet,
        .Config = config,
        .ExitNode = exitNode,
        .RelayName = relayName,
        .RemoteOutput = remoteOutput,
    };

    m_subject->Encapsulate(context);

    EXPECT_TRUE(remoteOutput.empty());
}

TEST_F(Given_HostedDnsService, When_ValidHostedDnsResponseArrives_Then_PacketIsInjected)
{
    tailgate::types::netmap::NetworkConfig config;
    config.SelfAddress = "100.64.0.1";
    const std::vector<std::uint8_t> dnsMessage =
        tailgate::net::dns::BuildDnsQuery("host.example.ts.net", TransactionId);
    const std::vector<std::uint8_t> packet =
        tailgate::net::packet::BuildUdpPacket(tailgate::net::dns::MagicDnsIpv4Address,
                                              SelfAddress,
                                              tailgate::net::dns::DnsPort,
                                              SourcePort,
                                              dnsMessage);
    const tailgate::hosted::Frame response{
        .Type = tailgate::hosted::MessageType::TailnetDnsResponse,
        .Payload = packet,
    };
    const tailgate::crypto::Bytes32 privateKey{};
    const tailgate::crypto::Bytes32 publicKey{};
    const std::string exitNode;
    std::vector<std::vector<std::uint8_t>> localOutput;
    std::vector<std::uint8_t> remoteOutput;
    bg::service::DecapsulationContext context{
        .Message = response,
        .Config = config,
        .NodePrivateKey = privateKey,
        .NodePublicKey = publicKey,
        .ExitNode = exitNode,
        .LocalOutput = localOutput,
        .RemoteOutput = remoteOutput,
    };

    m_subject->Decapsulate(context);

    EXPECT_EQ(localOutput, (std::vector<std::vector<std::uint8_t>>{packet}));
    EXPECT_TRUE(remoteOutput.empty());
}

} // namespace
} // namespace tailgate::uwp::tests
