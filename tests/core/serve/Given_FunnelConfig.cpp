#include <gtest/gtest.h>

#include <tailgate/protocol/ControlRequests.h>
#include <tailgate/serve/FunnelConfig.h>

TEST(Given_HostInfoWithFunnel, When_BuildingMapRequest_Then_IngressIsAdvertised)
{
    tailgate::protocol::HostInfo host;
    const tailgate::serve::FunnelConfig funnel =
        tailgate::serve::TlsTerminatedTcpFunnel(10000, 9000);
    host.Hostname = "fake-host";
    host.OperatingSystem = "fake-os";
    host.OperatingSystemVersion = "fake-version";
    host.Architecture = "fake-architecture";

    tailgate::serve::ApplyToHostInfo(funnel, host);
    host.Services.push_back(tailgate::protocol::HostService{.Protocol = "peerapi4", .Port = 41112});
    host.Services.push_back(tailgate::protocol::HostService{.Protocol = "peerapi6", .Port = 41112});
    host.Services.push_back(
        tailgate::protocol::HostService{.Protocol = "peerapi-dns-proxy", .Port = 1});
    const auto bytes =
        tailgate::protocol::BuildMapRequest("nodekey:test", "discokey:test", host, 1, true);
    const std::string request(bytes.begin(), bytes.end());

    EXPECT_TRUE(request.find("\"IngressEnabled\":true") != std::string::npos);
    EXPECT_TRUE(request.find("\"Proto\":\"peerapi4\"") != std::string::npos);
    EXPECT_TRUE(request.find("\"Proto\":\"peerapi6\"") != std::string::npos);
    EXPECT_TRUE(request.find("\"Proto\":\"peerapi-dns-proxy\"") != std::string::npos);
    EXPECT_TRUE(request.find("\"Port\":41112") != std::string::npos);
    EXPECT_TRUE(request.find("\"WireIngress\"") == std::string::npos);
}

TEST(Given_FunnelConfig, When_CheckingIngressTarget_Then_OnlyConfiguredHostPortMatches)
{
    const tailgate::serve::FunnelConfig funnel =
        tailgate::serve::TlsTerminatedTcpFunnel(10000, 9000);

    const bool exact = tailgate::serve::HasFunnelForTarget(
        funnel, "node.example.ts.net.", "node", "example.ts.net", "node.example.ts.net.:10000");
    const bool fallback = tailgate::serve::HasFunnelForTarget(
        funnel, "", "node", "example.ts.net", "node.example.ts.net:10000");
    const bool wrongPort = tailgate::serve::HasFunnelForTarget(
        funnel, "node.example.ts.net.", "node", "example.ts.net", "node.example.ts.net.:443");

    EXPECT_TRUE(exact);
    EXPECT_TRUE(fallback);
    EXPECT_FALSE(wrongPort);
}

TEST(Given_FunnelTarget, When_DerivingTlsHostname_Then_HostIsExtracted)
{
    const std::string dnsHost = tailgate::serve::HostFromTarget("relay.example.ts.net:10000");
    const std::string bracketedIpv6 = tailgate::serve::HostFromTarget("[fd7a:115c:a1e0::1]:443");
    const std::string rawIpv6 = tailgate::serve::HostFromTarget("fd7a:115c:a1e0::1");

    EXPECT_EQ("relay.example.ts.net", dnsHost);
    EXPECT_EQ("fd7a:115c:a1e0::1", bracketedIpv6);
    EXPECT_TRUE(rawIpv6.empty());
}
