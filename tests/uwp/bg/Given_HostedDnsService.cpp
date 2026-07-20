#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include <tailgate/network/Dns.h>
#include <tailgate/network/Ipv4.h>
#include <tailgate/network/TailnetDns.h>
#include <tailgate/relay/RelayProtocol.h>

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
    control::NetworkConfig config;
    config.SelfAddress = "100.64.0.1";
    const std::vector<std::uint8_t> query =
        network::BuildDnsQuery("host.example.ts.net", TransactionId);
    const std::vector<std::uint8_t> packet = network::BuildUdpPacket(
        SelfAddress, network::MagicDnsIpv4Address, SourcePort, network::DnsPort, query);
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
    relay::Decoder decoder;
    decoder.Feed(remoteOutput);
    const std::optional<relay::Frame> frame = decoder.Next();

    EXPECT_EQ(m_dataPlane->ServiceCount(), 1U);
    EXPECT_TRUE(frame.has_value());
    EXPECT_EQ(frame.value_or(relay::Frame{}).Type, relay::MessageType::TailnetDnsQuery);
    EXPECT_EQ(frame.value_or(relay::Frame{}).Payload, packet);
}

TEST_F(Given_HostedDnsService, When_QuerySourceDoesNotMatchSelf_Then_QueryIsDropped)
{
    control::NetworkConfig config;
    config.SelfAddress = "100.64.0.1";
    const std::vector<std::uint8_t> query =
        network::BuildDnsQuery("host.example.ts.net", TransactionId);
    const std::vector<std::uint8_t> packet = network::BuildUdpPacket(
        OtherAddress, network::MagicDnsIpv4Address, SourcePort, network::DnsPort, query);
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
    control::NetworkConfig config;
    config.SelfAddress = "100.64.0.1";
    const std::vector<std::uint8_t> dnsMessage =
        network::BuildDnsQuery("host.example.ts.net", TransactionId);
    const std::vector<std::uint8_t> packet = network::BuildUdpPacket(
        network::MagicDnsIpv4Address, SelfAddress, network::DnsPort, SourcePort, dnsMessage);
    const relay::Frame response{
        .Type = relay::MessageType::TailnetDnsResponse,
        .Payload = packet,
    };
    const protocol::Bytes32 privateKey{};
    const protocol::Bytes32 publicKey{};
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
