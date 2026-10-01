#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/DelegationLease.h>

#include "fakes/derp/FakeConnection.h"
#include "fakes/di/FakeNetworkBindings.h"

namespace tailgate
{
namespace
{

class Given_DelegationLease : public testing::Test, public ipn::ipnlocal::DerpTransportFactory
{
protected:
    Given_DelegationLease()
    {
        tests::fakes::InstallFakeNetworkBindings(Injector);
        Derps = std::make_unique<ipn::ipnlocal::DerpConnections>(
            Injector.create<wgengine::Session&>(), *this);
        Derps->Ensure(1, "derp.example.com", true);
        Derps->Ensure(2, "other.example.com", false);
        Subject = std::make_unique<ipn::ipnlocal::DelegationLease>(*Derps, Time);
        Subject->ApplyMap(7);
    }

    void SetNetworkInterface(const std::string&) override
    {
    }

    std::unique_ptr<derp::Connection>
    Create(int, const std::string&, bool, std::size_t index, bool enabled) override
    {
        auto connection = std::make_unique<tests::fakes::derp::FakeConnection>(
            base::EventToken{.Value = index + 1}, derp::DerpClient::Packet{});
        connection->SetEnabled(enabled);
        return connection;
    }

    hosted::DelegationRequest Request(hosted::DelegationAction action, std::uint64_t generation = 1)
    {
        return {.Generation = generation,
                .RequestId = ++Sequence,
                .MapRevision = 7,
                .Action = action,
                .Regions = {1, 2}};
    }

    void Prepare()
    {
        Subject->Accept(Request(hosted::DelegationAction::Prepare));
        (void)Subject->TakeOutput();
    }

    tests::fakes::derp::FakeConnection& Region(int id)
    {
        return dynamic_cast<tests::fakes::derp::FakeConnection&>(Derps->ForRegion(id));
    }

    std::optional<hosted::DelegationReply> Last()
    {
        const auto output = Subject->TakeOutput();
        return output.empty() ? std::nullopt : hosted::DecodeDelegationReply(output.back());
    }

    di::Injector Injector;
    tests::fakes::FakeTimeProvider Time;
    std::unique_ptr<ipn::ipnlocal::DerpConnections> Derps;
    std::unique_ptr<ipn::ipnlocal::DelegationLease> Subject;
    std::uint64_t Sequence = 0;
};

TEST_F(Given_DelegationLease, When_Preparing_Then_DoesNotReleaseExistingOwnership)
{
    Subject->Accept(Request(hosted::DelegationAction::Prepare));
    const auto reply = Last();
    ASSERT_TRUE(reply);

    EXPECT_EQ(reply->Status, hosted::DelegationStatus::Prepared);
    EXPECT_TRUE(Region(1).Enabled);
    EXPECT_TRUE(Region(2).Enabled);
}

TEST_F(Given_DelegationLease, When_Releasing_Then_DisablesAllRequestedRegionsBeforeAcknowledging)
{
    Prepare();

    Subject->Accept(Request(hosted::DelegationAction::Release));
    const auto reply = Last();
    ASSERT_TRUE(reply);

    EXPECT_EQ(reply->Status, hosted::DelegationStatus::Released);
    EXPECT_FALSE(Region(1).Enabled);
    EXPECT_FALSE(Region(2).Enabled);
}

TEST_F(Given_DelegationLease,
       When_NewMapAddsRegionAfterRelease_Then_NewSocketCannotAcquireOwnership)
{
    Prepare();
    Subject->Accept(Request(hosted::DelegationAction::Release));

    Derps->Ensure(3, "new.example.com", false);
    Subject->ApplyMap(8);

    EXPECT_FALSE(Region(3).Enabled);
}

TEST_F(Given_DelegationLease, When_Acquiring_Then_ReadinessWaitsForEveryRequestedRegion)
{
    Prepare();
    Region(2).Authenticated = false;

    Subject->Accept(Request(hosted::DelegationAction::Acquire));
    const auto early = Subject->TakeOutput();
    Region(2).Authenticated = true;
    Subject->Poll();
    const auto reply = Last();
    ASSERT_TRUE(reply);

    EXPECT_TRUE(early.empty());
    EXPECT_EQ(reply->Status, hosted::DelegationStatus::Ready);
}

TEST_F(Given_DelegationLease,
       When_LeaseExpiresAfterAcquire_Then_ReleasesWithoutStealingOwnershipBack)
{
    Prepare();
    Subject->Accept(Request(hosted::DelegationAction::Acquire));
    (void)Subject->TakeOutput();

    Time.Advance(std::chrono::seconds(20));
    Subject->Poll();
    const auto reply = Last();
    ASSERT_TRUE(reply);

    EXPECT_EQ(reply->Failure, hosted::DelegationFailure::LeaseExpired);
    EXPECT_FALSE(Region(1).Enabled);
    EXPECT_FALSE(Region(2).Enabled);
}

TEST_F(Given_DelegationLease, When_AcquiredOwnershipIsCommitted_Then_LeaseDeadlineDoesNotReleaseIt)
{
    Prepare();
    Subject->Accept(Request(hosted::DelegationAction::Acquire));

    Subject->Accept(Request(hosted::DelegationAction::Commit));
    Time.Advance(std::chrono::seconds(25));
    Subject->Poll();
    const auto reply = Last();
    ASSERT_TRUE(reply);

    EXPECT_EQ(reply->Status, hosted::DelegationStatus::Committed);
    EXPECT_TRUE(Region(1).Enabled);
}

TEST_F(Given_DelegationLease, When_MapRevisionIsStale_Then_RequestCannotChangeOwnership)
{
    Prepare();
    Subject->ApplyMap(8);

    Subject->Accept(Request(hosted::DelegationAction::Release));
    const auto reply = Last();
    ASSERT_TRUE(reply);

    EXPECT_EQ(reply->Failure, hosted::DelegationFailure::StaleMap);
    EXPECT_TRUE(Region(1).Enabled);
}

TEST_F(Given_DelegationLease, When_RequestIsRepeated_Then_ReplaysAcknowledgmentWithoutNewOwnership)
{
    Prepare();
    const auto request = Request(hosted::DelegationAction::Release);
    Subject->Accept(request);
    const auto first = Last();

    Subject->Accept(request);
    const auto second = Last();

    EXPECT_EQ(first, second);
    EXPECT_FALSE(Region(1).Enabled);
}

TEST_F(Given_DelegationLease, When_OldGenerationReappears_Then_RejectsIt)
{
    Prepare();
    Subject->Accept(Request(hosted::DelegationAction::Prepare, 2));
    (void)Subject->TakeOutput();

    Subject->Accept(Request(hosted::DelegationAction::Release, 1));
    const auto reply = Last();
    ASSERT_TRUE(reply);

    EXPECT_EQ(reply->Failure, hosted::DelegationFailure::StaleGeneration);
    EXPECT_TRUE(Region(1).Enabled);
}

TEST_F(Given_DelegationLease,
       When_PrepareRepeatsWithDifferentRequestInSameGeneration_Then_RejectsLeaseReset)
{
    Prepare();
    Subject->Accept(Request(hosted::DelegationAction::Acquire));
    (void)Subject->TakeOutput();

    Subject->Accept(Request(hosted::DelegationAction::Prepare));
    const auto reply = Last();
    ASSERT_TRUE(reply);

    EXPECT_EQ(reply->Failure, hosted::DelegationFailure::InvalidState);
}

TEST_F(Given_DelegationLease, When_CommitPrecedesReleaseOrAcquire_Then_RejectsIt)
{
    Prepare();

    Subject->Accept(Request(hosted::DelegationAction::Commit));
    const auto reply = Last();
    ASSERT_TRUE(reply);

    EXPECT_EQ(reply->Failure, hosted::DelegationFailure::InvalidState);
}

} // namespace

} // namespace tailgate
