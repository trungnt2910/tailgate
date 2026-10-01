#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/UnderlaySelection.h>

#include "fakes/base/FakeTimeProvider.h"

namespace tailgate
{
namespace
{

class Given_UnderlaySelection : public testing::Test
{
protected:
    tests::fakes::FakeTimeProvider Time;
    ipn::ipnlocal::UnderlaySelection Subject{Time};
    net::netmon::Snapshot Networks{
        .Generation = 1,
        .Networks = {{.Interface = "adapter-a", .Addresses = {"192.0.2.1"}},
                     {.Interface = "adapter-b", .Addresses = {"198.51.100.1"}}}};
};

TEST_F(Given_UnderlaySelection, When_PreferredAdapterIsUnreachable_Then_TriesAnotherCandidate)
{
    Subject.Start(Networks, "adapter-a");

    Time.Advance(std::chrono::seconds(15));
    const auto change = Subject.Poll(Networks, false);
    ASSERT_TRUE(change);
    ASSERT_TRUE(change->Network);

    EXPECT_EQ(change->Network->Interface, "adapter-b");
}

TEST_F(Given_UnderlaySelection, When_PathIsReady_Then_DoesNotRotateAdapters)
{
    Subject.Start(Networks, "adapter-a");

    Time.Advance(std::chrono::minutes(1));
    const auto change = Subject.Poll(Networks, true);

    EXPECT_FALSE(change);
}

TEST_F(Given_UnderlaySelection, When_SelectedAddressChanges_Then_ReplacesSocketsImmediately)
{
    Subject.Start(Networks, "adapter-a");
    Networks.Networks.front().Addresses = {"192.0.2.2"};
    ++Networks.Generation;

    const auto change = Subject.Poll(Networks, true);
    ASSERT_TRUE(change);
    ASSERT_TRUE(change->Network);

    EXPECT_EQ(change->Network->Interface, "adapter-a");
    EXPECT_EQ(change->Network->Addresses, (std::vector<std::string>{"192.0.2.2"}));
}

TEST_F(Given_UnderlaySelection,
       When_AllAdaptersDisappear_Then_ReportsOfflineWithoutOsRoutingFallback)
{
    Subject.Start(Networks, "adapter-a");
    Networks.Networks.clear();
    ++Networks.Generation;

    const auto change = Subject.Poll(Networks, true);
    ASSERT_TRUE(change);

    EXPECT_FALSE(change->Network);
    EXPECT_FALSE(Subject.Poll(Networks, false));
}

TEST_F(Given_UnderlaySelection, When_ConnectivityReturns_Then_RetriesImmediately)
{
    Subject.Start({.Generation = 1, .Networks = {}}, {});

    const auto change = Subject.Poll(Networks, false);
    ASSERT_TRUE(change);
    ASSERT_TRUE(change->Network);

    EXPECT_EQ(change->Network->Interface, "adapter-a");
}

TEST_F(Given_UnderlaySelection, When_UnrelatedAdapterChanges_Then_KeepsWorkingPath)
{
    Subject.Start(Networks, "adapter-a");
    Networks.Networks.back().Addresses = {"198.51.100.2"};
    ++Networks.Generation;

    const auto change = Subject.Poll(Networks, true);

    EXPECT_FALSE(change);
}

TEST_F(Given_UnderlaySelection, When_SnapshotUsesOsRouting_Then_PreservesPlatformChoice)
{
    Networks.Networks = {{.Interface = {}, .Addresses = {"192.0.2.1"}}};
    Subject.Start(Networks, {});

    Time.Advance(std::chrono::seconds(15));
    const auto change = Subject.Poll(Networks, false);
    ASSERT_TRUE(change);
    ASSERT_TRUE(change->Network);

    EXPECT_FALSE(change->Network->Interface);
}

} // namespace

} // namespace tailgate
