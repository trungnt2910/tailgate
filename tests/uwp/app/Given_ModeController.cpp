#include <gtest/gtest.h>

#include "app/controller/impl/ModeControllerImpl.h"

#include "fakes/app/controller/FakeSessionController.h"
#include "fakes/app/controller/FakeSettingsController.h"

#include "TestHost.h"

namespace tailgate::uwp::tests
{
namespace
{

class FakeModeRpcController final : public ModeRpcController
{
public:
    const ModeRpcState& GetState() const noexcept override
    {
        return State;
    }

    void Request(const winrt::hstring& address, const winrt::hstring& relay) override
    {
        Address = address;
        Relay = relay;
        ++Requests;
    }

    ModeRpcState State;
    winrt::hstring Address;
    winrt::hstring Relay;
    unsigned Requests = 0;
};

class Given_ModeController : public testing::Test
{
protected:
    FakeModeRpcController Rpc;
    FakeSessionController Session;
    FakeSettingsController Settings;
    ModeControllerImpl Subject{Rpc, Session, Settings};
};

TEST_F(Given_ModeController, When_Disconnected_Then_SavesModeForNextConnection)
{
    TestHost::RunOnUiThread(
        [&]
        {
            Subject.SetRelay(L"https://relay.example.com");
        });

    EXPECT_EQ(Settings.SetTailgateServerArgument, L"https://relay.example.com");
    EXPECT_EQ(Rpc.Requests, 0U);
    EXPECT_FALSE(Subject.GetState().Busy());
}

TEST_F(Given_ModeController, When_ConnectedModeChanges_Then_UsesRpcWithoutRestartingProfile)
{
    TestHost::RunOnUiThread(
        [&]
        {
            Session.GetState().Connected(true);
            Settings.GetState().SelfAddress(L"100.64.0.1");
        });

    TestHost::RunOnUiThread(
        [&]
        {
            Subject.SetRelay(L"https://relay.example.com");
        });

    EXPECT_EQ(Rpc.Requests, 1U);
    EXPECT_EQ(Rpc.Address, L"100.64.0.1");
    EXPECT_TRUE(Subject.GetState().Busy());
    EXPECT_FALSE(Session.LastConnect);
}

TEST_F(Given_ModeController, When_UrlIsInvalid_Then_DoesNotSendRequestOrChangeSettings)
{
    TestHost::RunOnUiThread(
        [&]
        {
            Subject.SetRelay(L"http://relay.example.com");
        });

    EXPECT_EQ(Subject.GetState().Result(), app_service::Status::InvalidRelay);
    EXPECT_EQ(Rpc.Requests, 0U);
    EXPECT_FALSE(Settings.SetTailgateServerArgument);
}

TEST_F(Given_ModeController,
       When_BackgroundReportsRollback_Then_PreservesDesiredAndEffectiveDistinction)
{
    using tailgate::ipn::ipnlocal::NodeMode;
    using tailgate::ipn::ipnlocal::TransitionFailure;
    using tailgate::ipn::ipnlocal::TransitionPhase;
    app_service::ModeResponse response{.Result = app_service::Status::Ok,
                                       .Sequence = 1,
                                       .Transition = {.Desired = NodeMode::Native,
                                                      .Effective = NodeMode::Hosted,
                                                      .Phase = TransitionPhase::Failed,
                                                      .Failure = TransitionFailure::Timeout,
                                                      .Generation = 2,
                                                      .RollingBack = true}};

    TestHost::RunOnUiThread(
        [&]
        {
            Rpc.State.Response(response);
        });

    EXPECT_EQ(Subject.GetState().Transition(), response.Transition);
    EXPECT_FALSE(Subject.GetState().Busy());
    EXPECT_FALSE(Session.LastConnect);
}

TEST_F(Given_ModeController, When_HostedServerChanges_Then_UsesExplicitProfileReconnect)
{
    TestHost::RunOnUiThread(
        [&]
        {
            Session.GetState().Connected(true);
            Settings.GetState().SelfAddress(L"100.64.0.1");
            Settings.GetState().TailgateServer(L"https://old.example.com");
        });

    TestHost::RunOnUiThread(
        [&]
        {
            Subject.SetRelay(L"https://new.example.com");
        });

    EXPECT_TRUE(Session.LastConnect);
    EXPECT_EQ(Rpc.Requests, 0U);
}

} // namespace
} // namespace tailgate::uwp::tests
