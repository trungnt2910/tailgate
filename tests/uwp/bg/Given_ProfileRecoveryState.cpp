#include <gtest/gtest.h>

#include "bg/manager/ProfileRecoveryState.h"

namespace tailgate::uwp::tests
{
namespace
{

class Given_ProfileRecoveryState : public ::testing::Test
{
protected:
    bg::manager::ProfileRecoveryState State;
};

TEST_F(Given_ProfileRecoveryState, When_ConnectIsActive_Then_RecoveryWaitsForCallbackReturn)
{
    State.EnterConnect();
    ASSERT_TRUE(State.Request());
    State.AttemptTerminated();

    const bool before = State.Claim();
    State.LeaveConnect();
    const bool after = State.Claim();

    EXPECT_FALSE(before);
    EXPECT_TRUE(after);
}

TEST_F(Given_ProfileRecoveryState, When_RecoveryDisconnects_Then_RedialRemainsAllowed)
{
    ASSERT_TRUE(State.Request());
    State.AttemptTerminated();
    ASSERT_TRUE(State.Claim());

    const bool cancelled = State.Disconnecting();
    const bool dial = State.BeginDial();
    const bool nested = State.Request();

    EXPECT_FALSE(cancelled);
    EXPECT_TRUE(dial);
    EXPECT_FALSE(nested);
}

TEST_F(Given_ProfileRecoveryState, When_DisconnectArrivesDuringRedial_Then_RecoveryIsCancelled)
{
    ASSERT_TRUE(State.Request());
    State.AttemptTerminated();
    ASSERT_TRUE(State.Claim());
    ASSERT_TRUE(State.BeginDial());

    const bool cancelled = State.Disconnecting();
    const bool nested = State.Request();
    const bool dial = State.BeginDial();
    State.Finish();
    const bool later = State.Request();

    EXPECT_TRUE(cancelled);
    EXPECT_FALSE(nested);
    EXPECT_FALSE(dial);
    EXPECT_TRUE(later);
}

TEST_F(Given_ProfileRecoveryState,
       When_FailedChannelDisconnectsBeforeClaim_Then_QueuedRecoveryStillRuns)
{
    ASSERT_TRUE(State.Request());
    State.AttemptTerminated();

    const bool cancelled = State.Disconnecting();
    const bool claimed = State.Claim();

    EXPECT_FALSE(cancelled);
    EXPECT_TRUE(claimed);
}

TEST_F(Given_ProfileRecoveryState, When_NewConnectSupersedesRequest_Then_StaleRecoveryCannotRun)
{
    ASSERT_TRUE(State.Request());
    State.AttemptTerminated();

    State.EnterConnect();
    State.LeaveConnect();
    const bool claimed = State.Claim();

    EXPECT_FALSE(claimed);
}

TEST_F(Given_ProfileRecoveryState, When_TwoDispatchersClaim_Then_OnlyOneRunsRecovery)
{
    ASSERT_TRUE(State.Request());
    State.AttemptTerminated();

    const bool first = State.Claim();
    const bool second = State.Claim();

    EXPECT_TRUE(first);
    EXPECT_FALSE(second);
}

TEST_F(Given_ProfileRecoveryState,
       When_FailedAttemptIsNotTerminated_Then_CallbackReturnCannotStartRedial)
{
    State.EnterConnect();
    ASSERT_TRUE(State.Request());

    State.LeaveConnect();
    const bool beforeTermination = State.Claim();
    State.AttemptTerminated();
    const bool afterTermination = State.Claim();

    EXPECT_FALSE(beforeTermination);
    EXPECT_TRUE(afterTermination);
}

TEST_F(Given_ProfileRecoveryState,
       When_NextAttemptFails_Then_PreviousTerminationDoesNotAuthorizeRedial)
{
    ASSERT_TRUE(State.Request());
    State.AttemptTerminated();
    ASSERT_TRUE(State.Claim());
    State.Finish();

    const bool requested = State.Request();
    const bool claimed = State.Claim();

    EXPECT_TRUE(requested);
    EXPECT_FALSE(claimed);
}

} // namespace
} // namespace tailgate::uwp::tests
