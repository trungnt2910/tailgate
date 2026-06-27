#include <gtest/gtest.h>

#include "tailgate/protocol/ControlRequests.h"

#include <string>

TEST(Tailgate, GivenControlRequest_WhenBuildingHostInfo_ThenPlatformValuesArePreserved)
{
    const tailgate::protocol::HostInfo host{
        "portable-host",
        "custom-os",
        "custom-version",
        "custom-architecture",
    };

    const std::vector<std::uint8_t> bytes =
        tailgate::protocol::BuildRegisterRequest("nodekey:test", "tskey-test", host);
    const std::string request(bytes.begin(), bytes.end());

    ASSERT_TRUE(request.find("portable-host") != std::string::npos);
    ASSERT_TRUE(request.find("custom-os") != std::string::npos);
    ASSERT_TRUE(request.find("custom-version") != std::string::npos);
    ASSERT_TRUE(request.find("custom-architecture") != std::string::npos);
    ASSERT_TRUE(request.find("\"IPNVersion\":\"Tailgate\"") != std::string::npos);
}

TEST(Tailgate, GivenLogoutRequest_WhenBuilding_ThenIdentityIsExpired)
{
    const tailgate::protocol::HostInfo host{"host", "linux", "1", "amd64"};

    const auto bytes = tailgate::protocol::BuildLogoutRequest("nodekey:test", host);
    const std::string request(bytes.begin(), bytes.end());

    ASSERT_TRUE(request.find("1970-01-01T00:02:03Z") != std::string::npos);
    ASSERT_TRUE(request.find("nodekey:test") != std::string::npos);
}

TEST(Tailgate, GivenMapRequest_WhenStreaming_ThenPresenceStreamIsRequested)
{
    const tailgate::protocol::HostInfo host{"host", "linux", "1", "amd64"};

    const auto bytes =
        tailgate::protocol::BuildMapRequest("nodekey:test", "discokey:test", host, 1, true);
    const std::string request(bytes.begin(), bytes.end());

    ASSERT_TRUE(request.find("\"Stream\":true") != std::string::npos);
    ASSERT_TRUE(request.find("\"KeepAlive\":true") != std::string::npos);
}
