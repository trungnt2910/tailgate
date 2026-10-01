#include <gtest/gtest.h>

#include <tailgate/net/packet/Ipv4.h>

#include "common/VpnConstants.h"
#include "service/ModeService.h"

#include "fakes/bg/manager/FakeDataPlaneManager.h"
#include "fakes/ipn/ipnlocal/FakeNodeBackend.h"

namespace tailgate::uwp::tests
{
namespace
{

class Given_ModeService : public testing::Test
{
protected:
    Given_ModeService()
    {
        Node.Config.SelfAddress("100.64.0.1");
    }

    void Send(const std::string& source = "100.64.0.1")
    {
        const auto packet = tailgate::net::packet::Ipv4UdpDatagram::Build(
            tailgate::net::Ipv4Address::Parse(source).HostOrder(),
            VpnConstants::Network::ServiceIpv4Address,
            12345,
            VpnConstants::AppService::Port,
            app_service::EncodeModeRequest({.Sequence = 42, .RelayUrl = ""}));
        const std::string empty;
        bg::service::EncapsulationContext context{
            .Original = packet, .Node = Node, .RelayName = empty, .ExitNode = empty};
        Subject.Encapsulate(context);
    }

    std::optional<app_service::ModeResponse> Response()
    {
        std::vector<std::vector<std::uint8_t>> output;
        Subject.FlushLocal(output);
        if (output.size() != 1)
        {
            return {};
        }
        const auto packet = tailgate::net::packet::Ipv4UdpDatagram::Parse(output.front());
        if (!packet)
        {
            return {};
        }
        const auto message = app_service::DecodeMessage(packet->Payload());
        return message ? app_service::DecodeModeResponse(*message) : std::nullopt;
    }

    FakeDataPlaneManager Manager;
    tailgate::tests::fakes::FakeNodeBackend Node;
    bg::service::ModeService Subject{Manager};
};

TEST_F(Given_ModeService, When_LocalHostRequestsNative_Then_QueuesRequestForSerializedOwner)
{
    Send();
    const auto request = Subject.GetState().Request;
    ASSERT_TRUE(request);

    Subject.AcknowledgeRequest();

    EXPECT_EQ(request->Sequence, 42U);
    EXPECT_TRUE(request->RelayUrl.empty());
    EXPECT_FALSE(Subject.GetState().Request);
}

TEST_F(Given_ModeService, When_PeerSpoofsAppRequest_Then_IgnoresIt)
{
    Send("100.64.0.2");

    EXPECT_FALSE(Subject.GetState().Request);
    EXPECT_FALSE(Subject.HasLocalOutput());
}

TEST_F(Given_ModeService, When_StatusChanges_Then_ReportsCorrelatedTypedTransition)
{
    Send();
    Subject.AcknowledgeRequest();
    tailgate::ipn::ipnlocal::TransitionStatus status;
    status.Desired = tailgate::ipn::ipnlocal::NodeMode::Native;
    status.Effective = tailgate::ipn::ipnlocal::NodeMode::Hosted;
    status.Phase = tailgate::ipn::ipnlocal::TransitionPhase::Releasing;

    Subject.Publish(status);
    const auto response = Response();
    ASSERT_TRUE(response);

    EXPECT_EQ(response->Sequence, 42U);
    EXPECT_EQ(response->Transition, status);
}

TEST_F(Given_ModeService,
       When_AnotherRequestArrivesDuringTransition_Then_RejectsItWithoutLosingSubscriber)
{
    Send();
    Subject.AcknowledgeRequest();

    Send();
    const auto response = Response();
    ASSERT_TRUE(response);

    EXPECT_EQ(response->Result, app_service::Status::Busy);
    EXPECT_FALSE(Subject.GetState().Request);
}

TEST_F(Given_ModeService, When_TerminalStatusWasDelivered_Then_AcceptsNextRequest)
{
    Send();
    Subject.AcknowledgeRequest();
    Subject.Publish({});
    (void)Response();

    Send();
    const auto request = Subject.GetState().Request;

    EXPECT_TRUE(request);
}

} // namespace
} // namespace tailgate::uwp::tests
