#include <gtest/gtest.h>

#include "tailgate/protocol/ReplayWindow.h"

TEST(Tailgate, GivenAuthenticatedCountersBeyondThirtyTwoPackets_WhenReordered_ThenTheyAreAccepted)
{
    tailgate::protocol::ReplayWindow window;

    const bool newestAccepted = window.Accept(1000);
    const bool reorderedAccepted = window.Accept(900);

    EXPECT_TRUE(newestAccepted);
    EXPECT_TRUE(reorderedAccepted);
}

TEST(Tailgate, GivenAuthenticatedCounter_WhenReceivedTwice_ThenReplayIsRejected)
{
    tailgate::protocol::ReplayWindow window;
    ASSERT_TRUE(window.Accept(42));

    const bool replayAccepted = window.Accept(42);

    EXPECT_FALSE(replayAccepted);
}

TEST(Tailgate, GivenCounterOlderThanWireGuardWindow_WhenReceived_ThenItIsRejected)
{
    tailgate::protocol::ReplayWindow window;
    ASSERT_TRUE(window.Accept(tailgate::protocol::ReplayWindow::WindowSize));

    const bool staleAccepted = window.Accept(0);

    EXPECT_FALSE(staleAccepted);
}

TEST(Tailgate, GivenWindowCrossingBitmapBoundary_WhenCountersAreReordered_ThenBitsRemainDistinct)
{
    tailgate::protocol::ReplayWindow window;
    ASSERT_TRUE(window.Accept(8191));
    ASSERT_TRUE(window.Accept(8193));

    const bool wrappedSlotAccepted = window.Accept(8192);
    const bool existingCounterAccepted = window.Accept(8191);

    EXPECT_TRUE(wrappedSlotAccepted);
    EXPECT_FALSE(existingCounterAccepted);
}
