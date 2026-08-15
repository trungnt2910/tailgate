#include <chrono>
#include <cstdint>

#include <gtest/gtest.h>

#include <tailgate/base/Clock.h>
#include <tailgate/wgengine/magicsock/PeerPathState.h>

namespace
{

constexpr std::uint16_t TestEndpointPort = 41641;

class FakeClock final : public tailgate::base::IClock
{
public:
    [[nodiscard]] TimePoint Now() const noexcept override
    {
        return m_now;
    }

    void Advance(Clock::duration duration) noexcept
    {
        m_now += duration;
    }

private:
    TimePoint m_now{};
};

tailgate::wgengine::magicsock::Endpoint MakeEndpoint(std::uint32_t address)
{
    return tailgate::wgengine::magicsock::Endpoint{
        .Address = address,
        .Port = TestEndpointPort,
    };
}

} // namespace

TEST(Given_PeerPathState, When_FirstProbeIsRequested_Then_ItStartsImmediately)
{
    FakeClock clock;
    tailgate::wgengine::magicsock::PeerPathState state;

    const bool started = state.TryBeginProbe(clock.Now());

    EXPECT_TRUE(started);
}

TEST(Given_PeerPathState, When_ProbeIntervalHasNotElapsed_Then_ProbeIsRateLimited)
{
    FakeClock clock;
    tailgate::wgengine::magicsock::PeerPathState state;
    ASSERT_TRUE(state.TryBeginProbe(clock.Now()));
    clock.Advance(tailgate::wgengine::magicsock::PeerPathState::DirectProbeInterval -
                  std::chrono::milliseconds(1));

    const bool started = state.TryBeginProbe(clock.Now());

    EXPECT_FALSE(started);
}

TEST(Given_PeerPathState, When_ProbeIntervalElapses_Then_AnotherProbeCanStart)
{
    FakeClock clock;
    tailgate::wgengine::magicsock::PeerPathState state;
    ASSERT_TRUE(state.TryBeginProbe(clock.Now()));
    clock.Advance(tailgate::wgengine::magicsock::PeerPathState::DirectProbeInterval);

    const bool started = state.TryBeginProbe(clock.Now());

    EXPECT_TRUE(started);
}

TEST(Given_PeerPathState, When_EndpointIsValidated_Then_ItBecomesDirectAndVerified)
{
    tailgate::wgengine::magicsock::PeerPathState state;
    const tailgate::wgengine::magicsock::Endpoint endpoint = MakeEndpoint(1);

    const bool changed = state.MarkDirect(endpoint);

    EXPECT_TRUE(changed);
    EXPECT_TRUE(state.HasDirectPath());
    EXPECT_EQ(state.DirectEndpoint(), endpoint);
    EXPECT_TRUE(state.IsVerified(endpoint));
}

TEST(Given_PeerPathState, When_SelectedEndpointIsValidatedAgain_Then_PathDoesNotChange)
{
    tailgate::wgengine::magicsock::PeerPathState state;
    const tailgate::wgengine::magicsock::Endpoint endpoint = MakeEndpoint(1);
    ASSERT_TRUE(state.MarkDirect(endpoint));

    const bool changed = state.MarkDirect(endpoint);

    EXPECT_FALSE(changed);
}

TEST(Given_PeerPathState, When_DirectTimeoutBoundaryIsReached_Then_PathRemainsSelected)
{
    FakeClock clock;
    tailgate::wgengine::magicsock::PeerPathState state;
    ASSERT_TRUE(state.MarkDirect(MakeEndpoint(1)));
    state.MarkDirectSend(clock.Now());
    clock.Advance(tailgate::wgengine::magicsock::PeerPathState::DirectPathTimeout);

    const bool expired = state.ExpireDirectPath(clock.Now());

    EXPECT_FALSE(expired);
    EXPECT_TRUE(state.HasDirectPath());
}

TEST(Given_PeerPathState, When_DirectResponseTimesOut_Then_PathFallsBackToRelay)
{
    FakeClock clock;
    tailgate::wgengine::magicsock::PeerPathState state;
    ASSERT_TRUE(state.MarkDirect(MakeEndpoint(1)));
    state.MarkDirectSend(clock.Now());
    clock.Advance(tailgate::wgengine::magicsock::PeerPathState::DirectPathTimeout +
                  std::chrono::milliseconds(1));

    const bool expired = state.ExpireDirectPath(clock.Now());

    EXPECT_TRUE(expired);
    EXPECT_FALSE(state.HasDirectPath());
}

TEST(Given_PeerPathState, When_DirectResponseArrives_Then_PendingTimeoutIsCancelled)
{
    FakeClock clock;
    tailgate::wgengine::magicsock::PeerPathState state;
    ASSERT_TRUE(state.MarkDirect(MakeEndpoint(1)));
    state.MarkDirectSend(clock.Now());
    state.MarkDirectReceive();
    clock.Advance(tailgate::wgengine::magicsock::PeerPathState::DirectPathTimeout +
                  std::chrono::seconds(1));

    const bool expired = state.ExpireDirectPath(clock.Now());

    EXPECT_FALSE(expired);
    EXPECT_TRUE(state.HasDirectPath());
}

TEST(Given_PeerPathState, When_VerifiedEndpointLimitIsExceeded_Then_OldestIsForgotten)
{
    tailgate::wgengine::magicsock::PeerPathState state;
    for (std::uint32_t index = 0;
         index < tailgate::wgengine::magicsock::PeerPathState::MaximumVerifiedEndpoints;
         ++index)
    {
        (void)state.MarkDirect(MakeEndpoint(index + 1));
    }
    const tailgate::wgengine::magicsock::Endpoint oldest = MakeEndpoint(1);
    const tailgate::wgengine::magicsock::Endpoint newest = MakeEndpoint(100);

    (void)state.MarkDirect(newest);

    EXPECT_FALSE(state.IsVerified(oldest));
    EXPECT_TRUE(state.IsVerified(newest));
}

TEST(Given_PeerPathState, When_PathResetsForEndpointChange_Then_VerificationIsRetained)
{
    tailgate::wgengine::magicsock::PeerPathState state;
    const tailgate::wgengine::magicsock::Endpoint endpoint = MakeEndpoint(1);
    ASSERT_TRUE(state.MarkDirect(endpoint));

    state.Reset(tailgate::wgengine::magicsock::PeerPathState::ResetMode::PreserveVerifiedEndpoints);

    EXPECT_FALSE(state.HasDirectPath());
    EXPECT_TRUE(state.IsVerified(endpoint));
}

TEST(Given_PeerPathState, When_PathResetsForIdentityChange_Then_VerificationIsForgotten)
{
    tailgate::wgengine::magicsock::PeerPathState state;
    const tailgate::wgengine::magicsock::Endpoint endpoint = MakeEndpoint(1);
    ASSERT_TRUE(state.MarkDirect(endpoint));

    state.Reset(tailgate::wgengine::magicsock::PeerPathState::ResetMode::ForgetVerifiedEndpoints);

    EXPECT_FALSE(state.HasDirectPath());
    EXPECT_FALSE(state.IsVerified(endpoint));
}
