#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/UnderlayResolver.h>

#include "fakes/base/FakeEventLoop.h"
#include "fakes/base/FakeTimeProvider.h"

namespace tailgate
{
namespace
{

class Given_UnderlayResolver : public testing::Test, public net::netmon::Resolver
{
protected:
    net::Endpoint Resolve(const std::string& host,
                          std::uint16_t port,
                          const std::optional<std::string>& network,
                          std::stop_token) override
    {
        Host = host;
        Interface = network;
        return net::Endpoint(net::Ipv4Address::Parse("192.0.2.1"), port);
    }

    tests::fakes::FakeEventLoop Events;
    tests::fakes::FakeTimeProvider Time;
    std::string Host;
    std::optional<std::string> Interface;
    ipn::ipnlocal::UnderlayResolver Subject{*this, Events, Time};
};

TEST_F(Given_UnderlayResolver, When_LookupCompletes_Then_OwnerReceivesEndpointOnWake)
{
    Subject.Start("stun.example.com", 3478, "adapter-a");

    const auto immediate = Subject.Poll();
    Events.WaitForWake(2);
    const auto endpoint = Subject.Poll();
    ASSERT_TRUE(endpoint);

    EXPECT_FALSE(immediate);
    EXPECT_EQ(endpoint->ToString(), "192.0.2.1:3478");
    EXPECT_EQ(Host, "stun.example.com");
    EXPECT_EQ(Interface, "adapter-a");
}

TEST_F(Given_UnderlayResolver, When_CompletedLookupIsCancelled_Then_ResultCannotAttachToNewNetwork)
{
    Subject.Start("stun.example.com", 3478, "adapter-a");
    (void)Subject.Poll();
    Events.WaitForWake(2);

    Subject.Cancel();
    const auto endpoint = Subject.Poll();

    EXPECT_FALSE(endpoint);
}

TEST_F(Given_UnderlayResolver, When_NetworkChanges_Then_OnlyLatestLookupIsPublished)
{
    Subject.Start("old.example.com", 3478, "adapter-a");
    (void)Subject.Poll();
    Events.WaitForWake(2);

    Subject.Start("new.example.com", 3479, "adapter-b");
    const auto old = Subject.Poll();
    Events.WaitForWake(4);
    const auto endpoint = Subject.Poll();
    ASSERT_TRUE(endpoint);

    EXPECT_FALSE(old);
    EXPECT_EQ(Host, "new.example.com");
    EXPECT_EQ(Interface, "adapter-b");
    EXPECT_EQ(endpoint->Port(), 3479);
}

} // namespace

} // namespace tailgate
