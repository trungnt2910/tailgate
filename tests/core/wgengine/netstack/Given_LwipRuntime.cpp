#include <chrono>
#include <cstdint>
#include <memory>

#include <gtest/gtest.h>

#include <lwip/ip.h>
#include <lwip/ip_addr.h>
#include <lwip/netif.h>
#include <lwip/priv/nd6_priv.h>
#include <lwip/tcp.h>

#include <tailgate/wgengine/netstack/Error.h>

#include "wgengine/netstack/impl/Runtime.h"
#include "wgengine/netstack/port/Hooks.h"

#include "fakes/di/FakeNetworkBindings.h"

namespace tailgate::tests
{
namespace netstack = wgengine::netstack;

class Given_LwipRuntime : public testing::Test
{
protected:
    Given_LwipRuntime()
    {
        fakes::InstallFakeNetworkBindings(injector);
    }

    di::Injector injector;
};

TEST_F(Given_LwipRuntime, When_ResolvedTwice_Then_RuntimeIsScopedToInjector)
{
    auto& first = injector.create<netstack::impl::Runtime&>();

    auto& second = injector.create<netstack::impl::Runtime&>();

    EXPECT_EQ(&first, &second);
    EXPECT_FALSE(first.Started());
}

TEST_F(Given_LwipRuntime, When_AnotherRuntimeStarts_Then_ActiveScopeIsProtected)
{
    auto& first = injector.create<netstack::impl::Runtime&>();
    first.Start();
    di::Injector otherInjector;
    fakes::InstallFakeNetworkBindings(otherInjector);
    auto& second = otherInjector.create<netstack::impl::Runtime&>();
    std::optional<netstack::Error> error;

    try
    {
        second.Start();
    }
    catch (const netstack::Exception& exception)
    {
        error = exception.Reason();
    }

    EXPECT_EQ(error, netstack::Error::RuntimeInUse);
    EXPECT_TRUE(first.Started());
    EXPECT_FALSE(second.Started());
}

TEST_F(Given_LwipRuntime, When_RuntimeStops_Then_AnotherScopeCanStart)
{
    auto& first = injector.create<netstack::impl::Runtime&>();
    first.Start();
    di::Injector otherInjector;
    fakes::InstallFakeNetworkBindings(otherInjector);
    auto& second = otherInjector.create<netstack::impl::Runtime&>();

    first.Stop();
    second.Start();
    second.Poll();

    EXPECT_FALSE(first.Started());
    EXPECT_TRUE(second.Started());
    EXPECT_FALSE(second.NextDeadline().has_value());
}

TEST_F(Given_LwipRuntime, When_TrackedPcbIsFreed_Then_RuntimeDoesNotRetainIt)
{
    auto& runtime = injector.create<netstack::impl::Runtime&>();
    runtime.Start();
    auto* pcb = tcp_new();
    ASSERT_NE(pcb, nullptr);
    ASSERT_TRUE(runtime.Track(pcb));
    ASSERT_EQ(runtime.ConnectionCount(), 1U);

    tcp_abort(pcb);

    EXPECT_EQ(runtime.ConnectionCount(), 0U);
}

TEST_F(Given_LwipRuntime, When_Ipv6PrefixExpires_Then_MaintenanceStops)
{
    auto& runtime = injector.create<netstack::impl::Runtime&>();
    runtime.Start();
    auto& clock = dynamic_cast<fakes::FakeTimeProvider&>(injector.create<base::TimeProvider&>());
    netif interface{};
    ASSERT_NE(netif_add_noaddr(
                  &interface,
                  nullptr,
                  [](netif*) -> err_t
                  {
                      return ERR_OK;
                  },
                  ip_input),
              nullptr);
    const std::unique_ptr<netif, decltype(&netif_remove)> registration(&interface, netif_remove);
    auto& prefix = prefix_list[0];
    ASSERT_EQ(prefix.netif, nullptr);
    ASSERT_NE(ip6addr_aton("2001:db8::", &prefix.prefix), 0);
    prefix.netif = &interface;
    prefix.invalidation_timer = 3;
    ASSERT_TRUE(runtime.NextDeadline());

    for (unsigned tick = 0; tick < 6; ++tick)
    {
        clock.Advance(std::chrono::seconds(1));
        runtime.Poll();
    }

    EXPECT_EQ(prefix.netif, nullptr);
    EXPECT_EQ(prefix.invalidation_timer, 0U);
    EXPECT_FALSE(runtime.NextDeadline());
}

TEST_F(Given_LwipRuntime, When_RuntimeStopsWithBoundPcb_Then_PortCanBeReused)
{
    auto& runtime = injector.create<netstack::impl::Runtime&>();
    runtime.Start();
    auto* original = tcp_new();
    ASSERT_NE(original, nullptr);
    ASSERT_TRUE(runtime.Track(original));
    constexpr std::uint16_t port = 8080;
    ASSERT_EQ(tcp_bind(original, IP_ANY_TYPE, port), ERR_OK);

    runtime.Stop();
    runtime.Start();
    auto* replacement = tcp_new();
    const bool tracked = replacement && runtime.Track(replacement);
    const auto bound = tracked ? tcp_bind(replacement, IP_ANY_TYPE, port) : ERR_MEM;
    if (replacement && !tracked)
    {
        tcp_abort(replacement);
    }

    EXPECT_TRUE(tracked);
    EXPECT_EQ(bound, ERR_OK);
    EXPECT_EQ(runtime.ConnectionCount(), 1U);
}

TEST_F(Given_LwipRuntime, When_ListenerIsTrackedAfterConversion_Then_StopReleasesItsPort)
{
    auto& runtime = injector.create<netstack::impl::Runtime&>();
    runtime.Start();
    auto* pcb = tcp_new();
    ASSERT_NE(pcb, nullptr);
    constexpr std::uint16_t port = 8080;
    ASSERT_EQ(tcp_bind(pcb, IP_ANY_TYPE, port), ERR_OK);
    auto* listener = tcp_listen(pcb);
    ASSERT_NE(listener, nullptr);
    ASSERT_TRUE(runtime.Track(listener));

    runtime.Stop();
    runtime.Start();
    auto* replacement = tcp_new();
    const bool tracked = replacement && runtime.Track(replacement);
    const auto bound = tracked ? tcp_bind(replacement, IP_ANY_TYPE, port) : ERR_MEM;
    if (replacement && !tracked)
    {
        tcp_abort(replacement);
    }

    EXPECT_TRUE(tracked);
    EXPECT_EQ(bound, ERR_OK);
}

TEST_F(Given_LwipRuntime, When_ClockAdvances_Then_SequenceSpaceAdvancesInFourMicrosecondTicks)
{
    auto& runtime = injector.create<netstack::impl::Runtime&>();
    runtime.Start();
    auto& clock = dynamic_cast<fakes::FakeTimeProvider&>(injector.create<base::TimeProvider&>());
    ip_addr_t local{};
    ip_addr_t remote{};
    ASSERT_NE(ipaddr_aton("192.0.2.1", &local), 0);
    ASSERT_NE(ipaddr_aton("192.0.2.2", &remote), 0);

    const auto first = tailgate_lwip_tcp_isn(&local, 8080, &remote, 49152);
    clock.Advance(std::chrono::microseconds(4));
    const auto second = tailgate_lwip_tcp_isn(&local, 8080, &remote, 49152);

    EXPECT_EQ(second - first, 1U);
}

TEST_F(Given_LwipRuntime, When_RuntimeRestarts_Then_SequenceSecretRemainsStable)
{
    auto& runtime = injector.create<netstack::impl::Runtime&>();
    runtime.Start();
    ip_addr_t local{};
    ip_addr_t remote{};
    ASSERT_NE(ipaddr_aton("2001:db8::1", &local), 0);
    ASSERT_NE(ipaddr_aton("2001:db8::2", &remote), 0);
    const auto first = tailgate_lwip_tcp_isn(&local, 8080, &remote, 49152);

    runtime.Stop();
    runtime.Start();
    const auto second = tailgate_lwip_tcp_isn(&local, 8080, &remote, 49152);

    EXPECT_EQ(second, first);
}

} // namespace tailgate::tests
