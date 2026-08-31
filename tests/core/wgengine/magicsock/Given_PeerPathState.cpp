#include <chrono>
#include <cstdint>

#include <gtest/gtest.h>

#include <tailgate/base/TimeProvider.h>
#include <tailgate/net/Endpoint.h>
#include <tailgate/wgengine/magicsock/PeerPathState.h>

#include "fakes/base/FakeTimeProvider.h"

namespace
{

constexpr std::uint16_t TestEndpointPort = 41641;
using tailgate::tests::fakes::FakeTimeProvider;

tailgate::net::Endpoint MakeEndpoint(std::uint8_t address)
{
    return tailgate::net::Endpoint(tailgate::net::Ipv4Address::FromOctets(192, 0, 2, address),
                                   TestEndpointPort);
}

} // namespace

TEST(Given_PeerPathState, When_FirstProbeIsRequested_Then_ItStartsImmediately)
{
    FakeTimeProvider clock;
    tailgate::wgengine::magicsock::PeerPathState state;

    const bool started = state.TryBeginProbe(clock.Now());

    EXPECT_TRUE(started);
}

TEST(Given_PeerPathState, When_ProbeIntervalHasNotElapsed_Then_ProbeIsRateLimited)
{
    FakeTimeProvider clock;
    tailgate::wgengine::magicsock::PeerPathState state;
    ASSERT_TRUE(state.TryBeginProbe(clock.Now()));
    clock.Advance(tailgate::wgengine::magicsock::PeerPathState::DirectProbeInterval -
                  std::chrono::milliseconds(1));

    const bool started = state.TryBeginProbe(clock.Now());

    EXPECT_FALSE(started);
}

TEST(Given_PeerPathState, When_ProbeIntervalElapses_Then_AnotherProbeCanStart)
{
    FakeTimeProvider clock;
    tailgate::wgengine::magicsock::PeerPathState state;
    ASSERT_TRUE(state.TryBeginProbe(clock.Now()));
    clock.Advance(tailgate::wgengine::magicsock::PeerPathState::DirectProbeInterval);

    const bool started = state.TryBeginProbe(clock.Now());

    EXPECT_TRUE(started);
}

TEST(Given_PeerPathState, When_EndpointIsValidated_Then_ItBecomesDirectAndVerified)
{
    tailgate::wgengine::magicsock::PeerPathState state;
    const tailgate::net::Endpoint endpoint = MakeEndpoint(1);

    const bool changed = state.MarkDirect(endpoint);

    EXPECT_TRUE(changed);
    EXPECT_TRUE(state.HasDirectPath());
    EXPECT_EQ(state.DirectEndpoint(), endpoint);
    EXPECT_TRUE(state.IsVerified(endpoint));
}

TEST(Given_PeerPathState, When_SelectedEndpointIsValidatedAgain_Then_PathDoesNotChange)
{
    tailgate::wgengine::magicsock::PeerPathState state;
    const tailgate::net::Endpoint endpoint = MakeEndpoint(1);
    ASSERT_TRUE(state.MarkDirect(endpoint));

    const bool changed = state.MarkDirect(endpoint);

    EXPECT_FALSE(changed);
}

TEST(Given_PeerPathState, When_DirectTimeoutBoundaryIsReached_Then_PathRemainsSelected)
{
    FakeTimeProvider clock;
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
    FakeTimeProvider clock;
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
    FakeTimeProvider clock;
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
    const tailgate::net::Endpoint oldest = MakeEndpoint(1);
    const tailgate::net::Endpoint newest = MakeEndpoint(100);

    (void)state.MarkDirect(newest);

    EXPECT_FALSE(state.IsVerified(oldest));
    EXPECT_TRUE(state.IsVerified(newest));
}

TEST(Given_PeerPathState, When_PathResetsForEndpointChange_Then_VerificationIsRetained)
{
    tailgate::wgengine::magicsock::PeerPathState state;
    const tailgate::net::Endpoint endpoint = MakeEndpoint(1);
    ASSERT_TRUE(state.MarkDirect(endpoint));

    state.Reset(tailgate::wgengine::magicsock::PeerPathState::ResetMode::PreserveVerifiedEndpoints);

    EXPECT_FALSE(state.HasDirectPath());
    EXPECT_TRUE(state.IsVerified(endpoint));
}

TEST(Given_PeerPathState, When_PathResetsForIdentityChange_Then_VerificationIsForgotten)
{
    tailgate::wgengine::magicsock::PeerPathState state;
    const tailgate::net::Endpoint endpoint = MakeEndpoint(1);
    ASSERT_TRUE(state.MarkDirect(endpoint));

    state.Reset(tailgate::wgengine::magicsock::PeerPathState::ResetMode::ForgetVerifiedEndpoints);

    EXPECT_FALSE(state.HasDirectPath());
    EXPECT_FALSE(state.IsVerified(endpoint));
}
