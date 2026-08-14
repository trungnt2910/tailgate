#include <gtest/gtest.h>

#include <tailgate/protocol/ReplayWindow.h>

TEST(Given_AuthenticatedCountersBeyondThirtyTwoPackets, When_Reordered_Then_TheyAreAccepted)
{
    tailgate::protocol::ReplayWindow window;

    const bool newestAccepted = window.Accept(1000);
    const bool reorderedAccepted = window.Accept(900);

    EXPECT_TRUE(newestAccepted);
    EXPECT_TRUE(reorderedAccepted);
}

TEST(Given_AuthenticatedCounter, When_ReceivedTwice_Then_ReplayIsRejected)
{
    tailgate::protocol::ReplayWindow window;
    ASSERT_TRUE(window.Accept(42));

    const bool replayAccepted = window.Accept(42);

    EXPECT_FALSE(replayAccepted);
}

TEST(Given_CounterOlderThanWireGuardWindow, When_Received_Then_ItIsRejected)
{
    tailgate::protocol::ReplayWindow window;
    ASSERT_TRUE(window.Accept(tailgate::protocol::ReplayWindow::WindowSize));

    const bool staleAccepted = window.Accept(0);

    EXPECT_FALSE(staleAccepted);
}

TEST(Given_WindowCrossingBitmapBoundary, When_CountersAreReordered_Then_BitsRemainDistinct)
{
    tailgate::protocol::ReplayWindow window;
    ASSERT_TRUE(window.Accept(8191));
    ASSERT_TRUE(window.Accept(8193));

    const bool wrappedSlotAccepted = window.Accept(8192);
    const bool existingCounterAccepted = window.Accept(8191);

    EXPECT_TRUE(wrappedSlotAccepted);
    EXPECT_FALSE(existingCounterAccepted);
}
