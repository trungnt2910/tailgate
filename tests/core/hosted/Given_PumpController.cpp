#include <chrono>
#include <optional>

#include <gtest/gtest.h>

#include <tailgate/di/Bindings.h>
#include <tailgate/hosted/PumpController.h>

#include "fakes/di/FakeNetworkBindings.h"

namespace tailgate::tests
{

class Given_PumpController : public testing::Test
{
protected:
    void SetUp() override
    {
        fakes::InstallFakeNetworkBindings(m_injector);
        m_subject = &m_injector.create<hosted::PumpController&>();
        m_clock = &m_injector.create<base::TimeProvider&>();
    }

    di::Injector m_injector;
    hosted::PumpController* m_subject = nullptr;
    base::TimeProvider* m_clock = nullptr;
};

TEST_F(Given_PumpController, When_CallbackFinishesAllWork_Then_NoPumpIsRequested)
{
    const bool localOutputPending = false;

    const auto request = m_subject->Update(localOutputPending, std::nullopt);

    EXPECT_FALSE(request.has_value());
}

TEST_F(Given_PumpController, When_LocalOutputIsQueued_Then_ImmediateRequestsAreCoalesced)
{
    const bool localOutputPending = true;

    const auto first = m_subject->Update(localOutputPending, std::nullopt);
    const auto repeated = m_subject->Update(localOutputPending, std::nullopt);
    ASSERT_TRUE(first);

    EXPECT_EQ(first->Delay, std::chrono::milliseconds::zero());
    EXPECT_FALSE(repeated.has_value());
}

TEST_F(Given_PumpController, When_OrdinaryTrafficServicesWork_Then_PendingPumpIsCancelled)
{
    const auto first = m_subject->Update(true, std::nullopt);
    ASSERT_TRUE(first.has_value());

    const auto cancelled = m_subject->Update(false, std::nullopt);
    const auto repeated = m_subject->Update(false, std::nullopt);
    ASSERT_TRUE(cancelled);

    EXPECT_GT(cancelled->RequestId, first->RequestId);
    EXPECT_FALSE(cancelled->Delay.has_value());
    EXPECT_FALSE(repeated.has_value());
}

TEST_F(Given_PumpController, When_DeadlineRemainsUnchanged_Then_OrdinaryTrafficDoesNotResendIt)
{
    const auto deadline = m_clock->Now() + std::chrono::milliseconds(250);

    const auto first = m_subject->Update(false, deadline);
    const auto repeated = m_subject->Update(false, deadline);
    ASSERT_TRUE(first);

    EXPECT_EQ(first->Delay, std::chrono::milliseconds(250));
    EXPECT_FALSE(repeated.has_value());
}

TEST_F(Given_PumpController,
       When_DeadlineSamplingJittersWithinWireResolution_Then_UpdateIsCoalesced)
{
    const auto deadline = m_clock->Now() + std::chrono::milliseconds(250);

    const auto first = m_subject->Update(false, deadline + std::chrono::microseconds(100));
    const auto repeated = m_subject->Update(false, deadline + std::chrono::microseconds(800));

    EXPECT_TRUE(first.has_value());
    EXPECT_EQ(first.value_or(hosted::PumpSchedule{}).Delay, std::chrono::milliseconds(251));
    EXPECT_FALSE(repeated.has_value());
}

TEST_F(Given_PumpController, When_DeadlineIsReplaced_Then_AnOldReplyCannotClearIt)
{
    const auto first = m_subject->Update(false, m_clock->Now() + std::chrono::seconds(1));
    ASSERT_TRUE(first.has_value());
    const auto deadline = m_clock->Now() + std::chrono::milliseconds(250);
    const auto replacement = m_subject->Update(false, deadline);
    ASSERT_TRUE(replacement.has_value());

    m_subject->Complete(first->RequestId);
    const auto repeated = m_subject->Update(false, deadline);

    EXPECT_GT(replacement->RequestId, first->RequestId);
    EXPECT_FALSE(repeated.has_value());
}

TEST_F(Given_PumpController, When_PumpCompletes_Then_RemainingWorkCanRequestAnother)
{
    const auto first = m_subject->Update(true, std::nullopt);
    ASSERT_TRUE(first.has_value());

    m_subject->Complete(first->RequestId);
    const auto next = m_subject->Update(true, std::nullopt);
    ASSERT_TRUE(next);

    EXPECT_GT(next->RequestId, first->RequestId);
    EXPECT_EQ(next->Delay, std::chrono::milliseconds::zero());
}

TEST_F(Given_PumpController, When_ControllerIsReset_Then_OldRepliesCannotCompleteNewWork)
{
    const auto first = m_subject->Update(true, std::nullopt);
    ASSERT_TRUE(first.has_value());

    m_subject->Reset();
    const auto next = m_subject->Update(true, std::nullopt);
    m_subject->Complete(first->RequestId);
    const auto repeated = m_subject->Update(true, std::nullopt);
    ASSERT_TRUE(next);

    EXPECT_GT(next->RequestId, first->RequestId);
    EXPECT_FALSE(repeated.has_value());
}

TEST_F(Given_PumpController, When_DeadlineIsFarAway_Then_WireDelayIsBounded)
{
    const auto deadline = m_clock->Now() + std::chrono::hours(1);

    const auto request = m_subject->Update(false, deadline);
    ASSERT_TRUE(request);

    EXPECT_EQ(request->Delay, hosted::MaximumPumpDelay);
}

} // namespace tailgate::tests
