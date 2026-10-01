#include <algorithm>

#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/TransitionCoordinator.h>

#include "fakes/base/FakeTimeProvider.h"

namespace tailgate
{
namespace
{

using ipn::ipnlocal::NodeMode;
using ipn::ipnlocal::TransitionActionKind;
using ipn::ipnlocal::TransitionCoordinator;
using ipn::ipnlocal::TransitionFailure;
using ipn::ipnlocal::TransitionPhase;

class Given_TransitionCoordinator : public testing::Test
{
protected:
    void BeginNative()
    {
        ASSERT_TRUE(Subject.Begin(NodeMode::Native, 7, {2, 1, 2}, true));
        Subject.MapApplied(7);
        Subject.Prepared(Subject.Status().Generation, true);
    }

    void Reply(hosted::DelegationStatus status)
    {
        auto actions = Subject.TakeActions();
        const auto found = std::ranges::find_if(actions,
                                                [](const auto& action)
                                                {
                                                    return action.Delegation.has_value();
                                                });
        ASSERT_NE(found, actions.end());
        const auto& request = *found->Delegation;
        Subject.Reply({.Generation = request.Generation,
                       .RequestId = request.RequestId,
                       .MapRevision = request.MapRevision,
                       .Status = status,
                       .Failure = status == hosted::DelegationStatus::Failed
                                      ? hosted::DelegationFailure::InvalidState
                                      : hosted::DelegationFailure::None});
    }

    tests::fakes::FakeTimeProvider Time;
    TransitionCoordinator Subject{Time, NodeMode::Hosted};
};

TEST_F(Given_TransitionCoordinator, When_BeginningNative_Then_PreparesWithoutChangingEffectiveMode)
{
    const auto accepted = Subject.Begin(NodeMode::Native, 7, {1}, true);
    const auto actions = Subject.TakeActions();

    EXPECT_TRUE(accepted);
    EXPECT_EQ(Subject.Status().Effective, NodeMode::Hosted);
    ASSERT_EQ(actions.size(), 1U);
    EXPECT_EQ(actions.front().Kind, TransitionActionKind::PrepareNative);
}

TEST_F(Given_TransitionCoordinator, When_CandidateHasStaleGeneration_Then_CannotAdvance)
{
    ASSERT_TRUE(Subject.Begin(NodeMode::Native, 7, {1}, true));

    Subject.Prepared(Subject.Status().Generation + 1, true);

    EXPECT_EQ(Subject.Status().Phase, TransitionPhase::Preparing);
}

TEST_F(Given_TransitionCoordinator, When_CandidatePreparedBeforeMapAck_Then_WaitsForExactRevision)
{
    ASSERT_TRUE(Subject.Begin(NodeMode::Native, 7, {1}, true));
    Subject.Prepared(Subject.Status().Generation, true);

    Subject.MapApplied(6);

    EXPECT_EQ(Subject.Status().Phase, TransitionPhase::AwaitingMap);
    EXPECT_EQ(Subject.Status().Effective, NodeMode::Hosted);
}

TEST_F(Given_TransitionCoordinator,
       When_MapWasAlreadyAcknowledged_Then_PreparesDelegationAfterCandidate)
{
    BeginNative();
    const auto actions = Subject.TakeActions();

    EXPECT_EQ(Subject.Status().Phase, TransitionPhase::PreparingDelegation);
    ASSERT_EQ(actions.size(), 2U);
    ASSERT_TRUE(actions.back().Delegation);
    EXPECT_EQ(actions.back().Delegation->Regions, (std::vector<std::uint16_t>{1, 2}));
    EXPECT_EQ(actions.back().Delegation->Action, hosted::DelegationAction::Prepare);
}

TEST_F(Given_TransitionCoordinator,
       When_DelegationPrepared_Then_ReleasePrecedesNativeAuthentication)
{
    BeginNative();

    Reply(hosted::DelegationStatus::Prepared);
    const auto actions = Subject.TakeActions();

    EXPECT_EQ(Subject.Status().Phase, TransitionPhase::Releasing);
    ASSERT_EQ(actions.size(), 1U);
    ASSERT_TRUE(actions.front().Delegation);
    EXPECT_EQ(actions.front().Delegation->Action, hosted::DelegationAction::Release);
}

TEST_F(Given_TransitionCoordinator,
       When_ReleaseAcknowledged_Then_ActivatesNativeButKeepsHostedSelection)
{
    BeginNative();
    Reply(hosted::DelegationStatus::Prepared);

    Reply(hosted::DelegationStatus::Released);
    const auto actions = Subject.TakeActions();

    EXPECT_EQ(Subject.Status().Effective, NodeMode::Hosted);
    ASSERT_EQ(actions.size(), 1U);
    EXPECT_EQ(actions.front().Kind, TransitionActionKind::ActivateNative);
}

TEST_F(Given_TransitionCoordinator, When_NativeReady_Then_SelectsAndCommitsBeforeRetiringRelay)
{
    BeginNative();
    Reply(hosted::DelegationStatus::Prepared);
    Reply(hosted::DelegationStatus::Released);
    (void)Subject.TakeActions();

    Subject.NativeReady(Subject.Status().Generation);
    const auto actions = Subject.TakeActions();

    EXPECT_EQ(Subject.Status().Effective, NodeMode::Native);
    EXPECT_EQ(Subject.Status().Phase, TransitionPhase::Committing);
    ASSERT_EQ(actions.size(), 2U);
    EXPECT_EQ(actions.front().Kind, TransitionActionKind::SelectNative);
    ASSERT_TRUE(actions.back().Delegation);
    EXPECT_EQ(actions.back().Delegation->Action, hosted::DelegationAction::Commit);
}

TEST_F(Given_TransitionCoordinator, When_CommitAcknowledged_Then_OldPathDrainsUntilDeadline)
{
    BeginNative();
    Reply(hosted::DelegationStatus::Prepared);
    Reply(hosted::DelegationStatus::Released);
    Subject.NativeReady(Subject.Status().Generation);
    Reply(hosted::DelegationStatus::Committed);

    Time.Advance(std::chrono::milliseconds(399));
    Subject.Poll();
    const auto early = Subject.TakeActions();
    Time.Advance(std::chrono::milliseconds(1));
    Subject.Poll();
    const auto final = Subject.TakeActions();

    EXPECT_TRUE(early.empty());
    EXPECT_EQ(Subject.Status().Phase, TransitionPhase::Idle);
    ASSERT_EQ(final.size(), 1U);
    EXPECT_EQ(final.front().Kind, TransitionActionKind::RetireHosted);
}

TEST_F(Given_TransitionCoordinator, When_CandidateTimesOut_Then_OriginalPathIsRetained)
{
    ASSERT_TRUE(Subject.Begin(NodeMode::Native, 7, {1}, true));
    (void)Subject.TakeActions();

    Time.Advance(std::chrono::seconds(15));
    Subject.Poll();
    const auto actions = Subject.TakeActions();

    EXPECT_EQ(Subject.Status().Effective, NodeMode::Hosted);
    EXPECT_EQ(Subject.Status().Failure, TransitionFailure::Timeout);
    ASSERT_EQ(actions.size(), 1U);
    EXPECT_EQ(actions.front().Kind, TransitionActionKind::RetireNative);
}

TEST_F(Given_TransitionCoordinator,
       When_CancelledAfterRelease_Then_NewGenerationReacquiresHostedOwnership)
{
    BeginNative();
    Reply(hosted::DelegationStatus::Prepared);
    Reply(hosted::DelegationStatus::Released);
    const auto generation = Subject.Status().Generation;

    Subject.Cancel();
    Reply(hosted::DelegationStatus::Prepared);
    const auto actions = Subject.TakeActions();

    EXPECT_GT(Subject.Status().Generation, generation);
    EXPECT_TRUE(Subject.Status().RollingBack);
    ASSERT_EQ(actions.size(), 1U);
    ASSERT_TRUE(actions.front().Delegation);
    EXPECT_EQ(actions.front().Delegation->Action, hosted::DelegationAction::Acquire);
}

TEST_F(Given_TransitionCoordinator, When_ReplyHasDifferentRequestId_Then_DoesNotReleaseOwnership)
{
    BeginNative();
    const auto actions = Subject.TakeActions();
    ASSERT_TRUE(actions.back().Delegation);
    auto request = *actions.back().Delegation;

    Subject.Reply({.Generation = request.Generation,
                   .RequestId = request.RequestId + 1,
                   .MapRevision = request.MapRevision,
                   .Status = hosted::DelegationStatus::Prepared});

    EXPECT_EQ(Subject.Status().Phase, TransitionPhase::PreparingDelegation);
    EXPECT_TRUE(Subject.TakeActions().empty());
}

TEST_F(Given_TransitionCoordinator,
       When_RelayDiesDuringPreparation_Then_DoesNotActivateUnpreparedNative)
{
    ASSERT_TRUE(Subject.Begin(NodeMode::Native, 7, {1}, true));
    (void)Subject.TakeActions();

    Subject.RelayFailed();
    const auto before = Subject.TakeActions();
    Subject.Prepared(Subject.Status().Generation, true);
    const auto after = Subject.TakeActions();

    ASSERT_EQ(before.size(), 1U);
    EXPECT_EQ(before.front().Kind, TransitionActionKind::RetireHosted);
    ASSERT_EQ(after.size(), 1U);
    EXPECT_EQ(after.front().Kind, TransitionActionKind::ActivateNative);
}

TEST_F(Given_TransitionCoordinator,
       When_NewRequestArrivesDuringTransition_Then_RejectsWithoutReplacingGeneration)
{
    BeginNative();
    const auto generation = Subject.Status().Generation;

    const auto accepted = Subject.Begin(NodeMode::Hosted, 7, {1}, true);

    EXPECT_FALSE(accepted);
    EXPECT_EQ(Subject.Status().Generation, generation);
    EXPECT_EQ(Subject.Status().Desired, NodeMode::Native);
}

TEST_F(Given_TransitionCoordinator, When_PolicyDiffers_Then_RejectsSeamlessTransition)
{
    const auto accepted = Subject.Begin(NodeMode::Native, 7, {1}, false);

    EXPECT_FALSE(accepted);
    EXPECT_EQ(Subject.Status().Failure, TransitionFailure::PolicyChanged);
    EXPECT_TRUE(Subject.TakeActions().empty());
}

TEST_F(Given_TransitionCoordinator,
       When_HostedCandidatePrepared_Then_SuspendsNativeBeforeSendingMap)
{
    TransitionCoordinator native(Time, NodeMode::Native);
    ASSERT_TRUE(native.Begin(NodeMode::Hosted, 1, {1}, true));
    (void)native.TakeActions();

    native.Prepared(native.Status().Generation, true);
    const auto actions = native.TakeActions();

    ASSERT_EQ(actions.size(), 2U);
    EXPECT_EQ(actions[0].Kind, TransitionActionKind::SuspendNative);
    EXPECT_EQ(actions[1].Kind, TransitionActionKind::ActivateHosted);
    EXPECT_EQ(native.Status().Effective, NodeMode::Native);
}

} // namespace

TEST_F(Given_TransitionCoordinator,
       When_MapChangesDuringRelease_Then_OldReleaseReplyCannotActivateNative)
{
    BeginNative();
    Reply(hosted::DelegationStatus::Prepared);
    auto actions = Subject.TakeActions();
    ASSERT_TRUE(actions.back().Delegation);
    const auto old = *actions.back().Delegation;

    Subject.MapChanged(8, {1, 2, 3});
    Subject.Reply({.Generation = old.Generation,
                   .RequestId = old.RequestId,
                   .MapRevision = old.MapRevision,
                   .Status = hosted::DelegationStatus::Released});

    EXPECT_GT(Subject.Status().Generation, old.Generation);
    EXPECT_EQ(Subject.Status().Phase, TransitionPhase::AwaitingMap);
    EXPECT_EQ(Subject.Status().Effective, NodeMode::Hosted);
}

TEST_F(Given_TransitionCoordinator,
       When_UnderlayForcesTransportRetirement_Then_AbortInvalidatesOutstandingCompletions)
{
    BeginNative();
    const auto generation = Subject.Status().Generation;

    Subject.Abort(TransitionFailure::Cancelled);
    Subject.Prepared(generation, true);

    EXPECT_EQ(Subject.Status().Phase, TransitionPhase::Failed);
    EXPECT_EQ(Subject.Status().Effective, NodeMode::Hosted);
    EXPECT_TRUE(Subject.TakeActions().empty());
}

} // namespace tailgate
