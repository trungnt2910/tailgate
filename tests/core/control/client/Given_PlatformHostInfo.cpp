#include <algorithm>
#include <string>

#include <gtest/gtest.h>

#include <tailgate/control/client/ControlRequests.h>

namespace
{

[[maybe_unused]] tailgate::control::client::HostInfo Host(std::string hostname = "host",
                                                          std::string operatingSystem = "linux",
                                                          std::string operatingSystemVersion = "1",
                                                          std::string architecture = "amd64")
{
    return tailgate::control::client::HostInfo(std::move(hostname),
                                               std::move(operatingSystem),
                                               std::move(operatingSystemVersion),
                                               std::move(architecture));
}

} // namespace

TEST(Given_PlatformHostInfo, When_ApplyingSessionConfig_Then_CapabilitiesAreAdded)
{
    tailgate::control::client::HostInfo host =
        Host("platform-host", "custom-os", "custom-version", "custom-architecture");
    tailgate::control::client::HostInfo config;
    config.SetHostname("configured-host");
    config.AddService(
        tailgate::control::client::HostService{.Protocol = "peerapi4", .Port = 41112});
    config.SetIngress(false, true);

    host.ApplySessionConfig(std::move(config));

    EXPECT_EQ(host.Hostname(), "configured-host");
    EXPECT_EQ(host.OperatingSystem(), "custom-os");
    ASSERT_EQ(host.Services().size(), 1U);
    EXPECT_EQ(host.Services().front().Protocol, "peerapi4");
    EXPECT_EQ(host.Services().front().Port, 41112);
    EXPECT_TRUE(host.IngressEnabled());
}
