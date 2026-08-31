#include <cerrno>

#include <gtest/gtest.h>

#include "Network.h"

TEST(Given_Network, When_AcceptIsInterrupted_Then_ItIsRetried)
{
    const tailgate::linux_frontend::AcceptFailureAction action =
        tailgate::linux_frontend::ClassifyAcceptFailure(EINTR, false);

    EXPECT_EQ(action, tailgate::linux_frontend::AcceptFailureAction::Retry);
}

TEST(Given_Network, When_AcceptReachesResourceLimit_Then_ListenerStops)
{
    const tailgate::linux_frontend::AcceptFailureAction action =
        tailgate::linux_frontend::ClassifyAcceptFailure(EMFILE, false);

    EXPECT_EQ(action, tailgate::linux_frontend::AcceptFailureAction::Stop);
}

TEST(Given_Network, When_AcceptFailsDuringShutdown_Then_ListenerStops)
{
    const tailgate::linux_frontend::AcceptFailureAction action =
        tailgate::linux_frontend::ClassifyAcceptFailure(EINTR, true);

    EXPECT_EQ(action, tailgate::linux_frontend::AcceptFailureAction::Stop);
}
