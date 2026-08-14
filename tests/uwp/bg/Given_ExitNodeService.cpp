#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include <tailgate/net/packet/Ipv4.h>

#include "common/Settings.h"
#include "common/UwpAppServiceProtocol.h"

#include "service/ExitNodeService.h"

#include "fakes/bg/manager/FakeDataPlaneManager.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

constexpr std::uint32_t AppAddress = 0x64400001U;
constexpr std::uint16_t AppPort = 49152;
constexpr std::uint64_t RequestSequence = 43;

std::optional<app_service::ExitNodeResponse>
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
    return message ? app_service::DecodeExitNodeResponse(*message) : std::nullopt;
}

class Given_ExitNodeService : public testing::Test
{
protected:
    void SetUp() override
    {
        Settings::Remove(L"PendingExitNodeChange");
        m_dataPlane = std::make_shared<FakeDataPlaneManager>();
        auto injector = di::make_injector(di::bind<bg::manager::DataPlaneManager>.to(
            [this](const auto&) -> bg::manager::DataPlaneManager&
            {
                return *m_dataPlane;
            }));
        m_subject = injector.create<std::unique_ptr<bg::service::ExitNodeService>>();
    }

    void TearDown() override
    {
        Settings::Remove(L"PendingExitNodeChange");
        Settings::Remove(L"ExitNode");
        Settings::Remove(L"ExitNodeSelection");
    }

    std::shared_ptr<FakeDataPlaneManager> m_dataPlane;
    std::unique_ptr<bg::service::ExitNodeService> m_subject;
};

TEST_F(Given_ExitNodeService, When_ExitNodeDoesNotExist_Then_RequestIsRejected)
{
    tailgate::net::packet::Ipv4UdpDatagram datagram;
    datagram.Source = AppAddress;
    datagram.SourcePort = AppPort;
    const app_service::ExitNodeRequest request{
        .Sequence = RequestSequence,
        .ExitNode = "missing.example.ts.net",
        .PreserveSelection = false,
    };
    const tailgate::types::netmap::NetworkConfig config;
    std::vector<std::vector<std::uint8_t>> appResponses;

    const bg::service::ExitNodeAction action =
        m_subject->Handle(datagram, request, config, "current", appResponses);
    const auto response = DecodeResponse(appResponses);

    EXPECT_EQ(m_dataPlane->ServiceCount(), 1U);
    EXPECT_EQ(action, bg::service::ExitNodeAction::Handled);
    EXPECT_EQ(appResponses.size(), 1U);
    EXPECT_TRUE(response.has_value());
    EXPECT_EQ(response.value_or(app_service::ExitNodeResponse{}).Result,
              app_service::Status::NoMatchingExitNode);
    EXPECT_EQ(response.value_or(app_service::ExitNodeResponse{}).Sequence, RequestSequence);
    EXPECT_EQ(response.value_or(app_service::ExitNodeResponse{}).ExitNode, "current");
}

TEST_F(Given_ExitNodeService, When_OnlineExitNodeExists_Then_ReconnectIsRequested)
{
    tailgate::net::packet::Ipv4UdpDatagram datagram;
    datagram.Source = AppAddress;
    datagram.SourcePort = AppPort;
    const app_service::ExitNodeRequest request{
        .Sequence = RequestSequence,
        .ExitNode = "exit",
        .PreserveSelection = false,
    };
    tailgate::types::netmap::PeerConfig peer;
    peer.Name = "exit.example.ts.net.";
    peer.Address = "100.64.0.2";
    peer.Online = true;
    peer.ExitNodeOption = true;
    tailgate::types::netmap::NetworkConfig config;
    config.Peers.push_back(peer);
    std::vector<std::vector<std::uint8_t>> appResponses;

    const bg::service::ExitNodeAction action =
        m_subject->Handle(datagram, request, config, "", appResponses);

    EXPECT_EQ(action, bg::service::ExitNodeAction::Reconnect);
    EXPECT_TRUE(appResponses.empty());
}

TEST_F(Given_ExitNodeService, When_AcceptedChangeCommits_Then_SuccessResponseIsQueued)
{
    tailgate::net::packet::Ipv4UdpDatagram datagram;
    datagram.Source = AppAddress;
    datagram.SourcePort = AppPort;
    const app_service::ExitNodeRequest request{
        .Sequence = RequestSequence,
        .ExitNode = "exit.example.ts.net",
        .PreserveSelection = false,
    };
    tailgate::types::netmap::PeerConfig peer;
    peer.Name = "exit.example.ts.net.";
    peer.Address = "100.64.0.2";
    peer.Online = true;
    peer.ExitNodeOption = true;
    tailgate::types::netmap::NetworkConfig config;
    config.Peers.push_back(peer);
    std::vector<std::vector<std::uint8_t>> ignoredResponses;
    const auto action = m_subject->Handle(datagram, request, config, "", ignoredResponses);
    ASSERT_EQ(action, bg::service::ExitNodeAction::Reconnect);
    std::string activeExitNode;
    std::vector<std::vector<std::uint8_t>> appResponses;

    m_subject->LoadPending(config, activeExitNode);
    m_subject->CommitPending(activeExitNode);
    m_subject->QueuePendingResponse(appResponses);
    const auto response = DecodeResponse(appResponses);

    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(activeExitNode, "exit");
    EXPECT_EQ(response->Result, app_service::Status::Ok);
    EXPECT_EQ(response->Sequence, RequestSequence);
    EXPECT_EQ(response->ExitNode, "exit");
    EXPECT_EQ(Settings::GetString(L"ExitNode"), L"exit");
    EXPECT_EQ(Settings::GetString(L"ExitNodeSelection"), L"exit");
}

TEST_F(Given_ExitNodeService, When_ExitNodeIsOffline_Then_RequestIsRejected)
{
    tailgate::net::packet::Ipv4UdpDatagram datagram;
    datagram.Source = AppAddress;
    datagram.SourcePort = AppPort;
    const app_service::ExitNodeRequest request{
        .Sequence = RequestSequence,
        .ExitNode = "offline",
        .PreserveSelection = false,
    };
    tailgate::types::netmap::PeerConfig peer;
    peer.Name = "offline.example.ts.net.";
    peer.Address = "100.64.0.3";
    peer.Online = false;
    peer.ExitNodeOption = true;
    tailgate::types::netmap::NetworkConfig config;
    config.Peers.push_back(peer);
    std::vector<std::vector<std::uint8_t>> appResponses;

    const auto action = m_subject->Handle(datagram, request, config, "current", appResponses);
    const auto response = DecodeResponse(appResponses);

    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(action, bg::service::ExitNodeAction::Handled);
    EXPECT_EQ(response->Result, app_service::Status::NoMatchingExitNode);
    EXPECT_EQ(response->ExitNode, "current");
}

} // namespace
} // namespace tailgate::uwp::tests
