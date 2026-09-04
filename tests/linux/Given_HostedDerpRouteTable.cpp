#include <cstdint>
#include <optional>

#include <gtest/gtest.h>

#include <tailgate/hosted/Protocol.h>
#include <tailgate/wgengine/Session.h>

#include "HostedDerpRouteTable.h"

TEST(Given_HostedDerpRouteTable, When_RouteIsReturned_Then_ExactIngressConnectionIsResolved)
{
    constexpr tailgate::wgengine::DerpConnectionId FirstConnection = 4;
    constexpr tailgate::wgengine::DerpConnectionId SecondConnection = 9;
    constexpr std::uint16_t DerpRegion = 5;
    tailgate::linux_frontend::HostedDerpRouteTable subject;
    const tailgate::hosted::DerpRoute first = subject.Register(FirstConnection, DerpRegion);
    const tailgate::hosted::DerpRoute second = subject.Register(SecondConnection, DerpRegion);

    const std::optional<tailgate::wgengine::DerpConnectionId> firstResult = subject.Resolve(first);
    const std::optional<tailgate::wgengine::DerpConnectionId> secondResult =
        subject.Resolve(second);

    EXPECT_EQ(firstResult, FirstConnection);
    EXPECT_EQ(secondResult, SecondConnection);
}

TEST(Given_HostedDerpRouteTable, When_PreviousGenerationRouteIsReturned_Then_RouteIsRejected)
{
    constexpr tailgate::wgengine::DerpConnectionId Connection = 4;
    constexpr std::uint16_t DerpRegion = 5;
    tailgate::linux_frontend::HostedDerpRouteTable previousGeneration;
    const tailgate::hosted::DerpRoute stale = previousGeneration.Register(Connection, DerpRegion);
    tailgate::linux_frontend::HostedDerpRouteTable currentGeneration;
    (void)currentGeneration.Register(Connection, DerpRegion);

    const std::optional<tailgate::wgengine::DerpConnectionId> result =
        currentGeneration.Resolve(stale);

    EXPECT_FALSE(result.has_value());
}

TEST(Given_HostedDerpRouteTable, When_RouteRegionIsChanged_Then_RouteIsRejected)
{
    constexpr tailgate::wgengine::DerpConnectionId Connection = 4;
    constexpr std::uint16_t DerpRegion = 5;
    tailgate::linux_frontend::HostedDerpRouteTable subject;
    const tailgate::hosted::DerpRoute route = subject.Register(Connection, DerpRegion);
    const tailgate::hosted::DerpRoute changedRegion(route.Token(), DerpRegion + 1);

    const std::optional<tailgate::wgengine::DerpConnectionId> result =
        subject.Resolve(changedRegion);

    EXPECT_FALSE(result.has_value());
}
