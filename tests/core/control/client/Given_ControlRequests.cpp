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

TEST(Given_ControlRequests, When_ControlRequestAndBuildingHostInfo_Then_PlatformValuesArePreserved)
{
    const tailgate::control::client::HostInfo host =
        Host("portable-host", "custom-os", "custom-version", "custom-architecture");

    const std::vector<std::uint8_t> bytes =
        tailgate::control::client::ControlRequest::BuildRegister(
            "nodekey:test", "tskey-test", host);
    const std::string request(bytes.begin(), bytes.end());

    EXPECT_TRUE(request.find("portable-host") != std::string::npos);
    EXPECT_TRUE(request.find("custom-os") != std::string::npos);
    EXPECT_TRUE(request.find("custom-version") != std::string::npos);
    EXPECT_TRUE(request.find("custom-architecture") != std::string::npos);
    EXPECT_TRUE(request.find("\"IPNVersion\":\"Tailgate\"") != std::string::npos);
}

TEST(Given_ControlRequests, When_RegisterRequestAndBuilding_Then_NodeIsNotForcedEphemeral)
{
    const tailgate::control::client::HostInfo host = Host();

    const auto bytes = tailgate::control::client::ControlRequest::BuildRegister(
        "nodekey:test", "tskey-test", host);
    const std::string request(bytes.begin(), bytes.end());

    EXPECT_TRUE(request.find("\"Ephemeral\"") == std::string::npos);
}

TEST(Given_ControlRequests,
     When_ExistingIdentityWithoutAuthKeyAndBuildingRegisterRequest_Then_AuthIsOmitted)
{
    const tailgate::control::client::HostInfo host = Host();

    const auto bytes =
        tailgate::control::client::ControlRequest::BuildRegister("nodekey:test", "", host);
    const std::string request(bytes.begin(), bytes.end());

    EXPECT_EQ(request.find("\"Auth\""), std::string::npos);
    EXPECT_EQ(request.find("\"AuthKey\""), std::string::npos);
}

TEST(Given_ControlRequests, When_PendingLoginAndBuildingRegisterRequest_Then_FollowupReplacesAuth)
{
    const tailgate::control::client::HostInfo host = Host();

    const auto bytes = tailgate::control::client::ControlRequest::BuildRegister(
        "nodekey:test", "tskey-test", "https://login.tailscale.com/a/fake-login-code", host);
    const std::string request(bytes.begin(), bytes.end());

    EXPECT_NE(request.find("\"Followup\":\"https://login.tailscale.com/a/fake-login-code\""),
              std::string::npos);
    EXPECT_EQ(request.find("\"Auth\""), std::string::npos);
    EXPECT_EQ(request.find("\"AuthKey\""), std::string::npos);
}

TEST(Given_ControlRequests, When_OfficialLoginUrlAndValidatingAuthorizationUrl_Then_ItIsAccepted)
{
    const std::vector<std::string_view> urls{
        "https://login.tailscale.com/a/fake-login-code",
        "https://LOGIN.TAILSCALE.COM:443/a/fake-login-code",
    };

    const bool allValid =
        std::all_of(urls.begin(),
                    urls.end(),
                    [](std::string_view url)
                    {
                        return tailgate::control::client::IsValidAuthorizationUrl(url);
                    });

    EXPECT_TRUE(allValid);
}

TEST(Given_ControlRequests, When_UntrustedLoginUrlAndValidatingAuthorizationUrl_Then_ItIsRejected)
{
    const std::vector<std::string_view> urls{
        "http://login.tailscale.com/a/code",
        "https://login.tailscale.com.example.com/a/code",
        "https://tailscale.com@evil.example.com/a/code",
        "https://.login.tailscale.com/a/code",
        "https://login.tailscale.com:/a/code",
        "https://login.tailscale.com:443:444/a/code",
        "https://login.tailscale.com/a/code\nhttps://evil.example.com",
        "https://login.tailscale.com\\@evil.example.com/a/code",
        "javascript:alert(1)",
    };

    const bool anyValid =
        std::any_of(urls.begin(),
                    urls.end(),
                    [](std::string_view url)
                    {
                        return tailgate::control::client::IsValidAuthorizationUrl(url);
                    });

    EXPECT_FALSE(anyValid);
}

TEST(Given_ControlRequests, When_OfficialLoginUrlAndExtractingAuthorizationCode_Then_CodeIsReturned)
{
    constexpr std::string_view url = "https://login.tailscale.com/a/fake-login-code";

    const std::string code = tailgate::control::client::AuthorizationCode(url);

    EXPECT_EQ(code, "fake-login-code");
}

TEST(Given_ControlRequests,
     When_NonstandardLoginUrlAndExtractingAuthorizationCode_Then_CodeIsOmitted)
{
    constexpr std::string_view url = "https://controlplane.example.com/a/code";

    const std::string code = tailgate::control::client::AuthorizationCode(url);

    EXPECT_TRUE(code.empty());
}

TEST(Given_ControlRequests, When_MachineAddressAndBuildingApprovalUrl_Then_DevicePageIsReturned)
{
    constexpr std::string_view address = "100.64.0.7";

    const std::string url = tailgate::control::client::MachineApprovalUrl(address);

    EXPECT_EQ(url, "https://login.tailscale.com/admin/machines/100.64.0.7");
}

TEST(Given_ControlRequests,
     When_MissingMachineAddressAndBuildingApprovalUrl_Then_MachinesPageIsReturned)
{
    constexpr std::string_view address;

    const std::string url = tailgate::control::client::MachineApprovalUrl(address);

    EXPECT_EQ(url, "https://login.tailscale.com/admin/machines");
}

TEST(Given_ControlRequests, When_SuccessfulRegisterResponseAndParsing_Then_StatusIsPreserved)
{
    const std::string json =
        R"({"MachineAuthorized":true,"NodeKeyExpired":false,"AuthURL":"","Error":""})";
    const std::vector<std::uint8_t> bytes(json.begin(), json.end());

    const std::optional<tailgate::control::client::RegisterResponse> response =
        tailgate::control::client::RegisterResponse::Parse(bytes);

    EXPECT_TRUE(response.has_value());
    EXPECT_TRUE(response->MachineAuthorized());
    EXPECT_FALSE(response->NodeKeyExpired());
    EXPECT_TRUE(response->AuthUrl().empty());
    EXPECT_TRUE(response->Error().empty());
}

TEST(Given_ControlRequests, When_RejectedRegisterResponseAndParsing_Then_ErrorIsPreserved)
{
    const std::string json = R"({"Error":"invalid auth key"})";
    const std::vector<std::uint8_t> bytes(json.begin(), json.end());

    const std::optional<tailgate::control::client::RegisterResponse> response =
        tailgate::control::client::RegisterResponse::Parse(bytes);

    EXPECT_TRUE(response.has_value());
    EXPECT_EQ(response->Error(), "invalid auth key");
}

TEST(Given_ControlRequests, When_MalformedRegisterResponseAndParsing_Then_ItIsRejected)
{
    const std::vector<std::uint8_t> bytes{'n', 'o', 't', '-', 'j', 's', 'o', 'n'};

    const std::optional<tailgate::control::client::RegisterResponse> response =
        tailgate::control::client::RegisterResponse::Parse(bytes);

    EXPECT_FALSE(response.has_value());
}

TEST(Given_ControlRequests, When_InitialMapCannotFindNewNodeAndClassifying_Then_ItIsRetryable)
{
    constexpr int status = 404;
    constexpr std::string_view response = "node not found\n";

    const bool retryable = tailgate::control::client::IsRetryableInitialMapError(status, response);

    EXPECT_TRUE(retryable);
}

TEST(Given_ControlRequests, When_UnrelatedMapFailureAndClassifying_Then_ItIsNotRetryable)
{
    constexpr int status = 404;
    constexpr std::string_view response = "tailnet not found";

    const bool retryable = tailgate::control::client::IsRetryableInitialMapError(status, response);

    EXPECT_FALSE(retryable);
}

TEST(Given_ControlRequests, When_LogoutRequestAndBuilding_Then_IdentityIsExpired)
{
    const tailgate::control::client::HostInfo host = Host();

    const auto bytes = tailgate::control::client::ControlRequest::BuildLogout("nodekey:test", host);
    const std::string request(bytes.begin(), bytes.end());

    EXPECT_TRUE(request.find("1970-01-01T00:02:03Z") != std::string::npos);
    EXPECT_TRUE(request.find("nodekey:test") != std::string::npos);
}

TEST(Given_ControlRequests, When_MapRequestAndStreaming_Then_PresenceStreamIsRequested)
{
    const tailgate::control::client::HostInfo host = Host();

    const auto bytes = tailgate::control::client::ControlRequest::BuildMap(
        "nodekey:test", "discokey:test", host, 1, true);
    const std::string request(bytes.begin(), bytes.end());

    EXPECT_TRUE(request.find("\"Stream\":true") != std::string::npos);
    EXPECT_TRUE(request.find("\"KeepAlive\":true") != std::string::npos);
}

TEST(Given_ControlRequests, When_MapRequestAndOmittingPeers_Then_ItCanUpdateHostInfo)
{
    const tailgate::control::client::HostInfo host = Host();

    const auto bytes = tailgate::control::client::ControlRequest::BuildMap(
        "nodekey:test", "discokey:test", host, 0, false, true);
    const std::string request(bytes.begin(), bytes.end());

    EXPECT_TRUE(request.find("\"Stream\"") == std::string::npos);
    EXPECT_TRUE(request.find("\"OmitPeers\":true") != std::string::npos);
    EXPECT_TRUE(request.find("\"Hostinfo\"") != std::string::npos);
}

TEST(Given_ControlRequests,
     When_ReadOnlyMapRequestAndBuilding_Then_ItFetchesPeersWithoutUpdatingTheNode)
{
    const tailgate::control::client::HostInfo host = Host();

    const auto bytes = tailgate::control::client::ControlRequest::BuildReadOnlyMap(
        "nodekey:test", "discokey:test", host);
    const std::string request(bytes.begin(), bytes.end());

    EXPECT_TRUE(request.find("\"ReadOnly\":true") != std::string::npos);
    EXPECT_TRUE(request.find("\"OmitPeers\"") == std::string::npos);
    EXPECT_TRUE(request.find("\"Stream\"") == std::string::npos);
}

TEST(Given_ControlRequests, When_LiteMapRequestAndBuilding_Then_KeepAliveAndEndpointsAreSent)
{
    const tailgate::control::client::HostInfo host = Host();
    const std::vector<tailgate::control::client::MapEndpoint> endpoints{
        tailgate::control::client::MapEndpoint{.AddressPort = "203.0.113.10:41641",
                                               .Type =
                                                   tailgate::control::client::EndpointType::Stun},
        tailgate::control::client::MapEndpoint{.AddressPort = "192.0.2.10:41641",
                                               .Type =
                                                   tailgate::control::client::EndpointType::Local}};

    const auto bytes = tailgate::control::client::ControlRequest::BuildMap(
        "nodekey:test", "discokey:test", host, 5, false, true, endpoints);
    const std::string request(bytes.begin(), bytes.end());

    EXPECT_TRUE(request.find("\"OmitPeers\":true") != std::string::npos);
    EXPECT_TRUE(request.find("\"KeepAlive\":true") != std::string::npos);
    EXPECT_TRUE(request.find("\"Compress\"") == std::string::npos);
    EXPECT_TRUE(request.find("\"PreferredDERP\":5") != std::string::npos);
    EXPECT_TRUE(request.find("\"WorkingUDP\":true") != std::string::npos);
    EXPECT_TRUE(request.find("\"Endpoints\":[\"203.0.113.10:41641\",\"192.0.2.10:41641\"]") !=
                std::string::npos);
    EXPECT_TRUE(request.find("\"EndpointTypes\":[2,1]") != std::string::npos);
}

TEST(Given_ControlRequests, When_MapRequestWithEndpointsAndBuilding_Then_EndpointTypesAreSent)
{
    const tailgate::control::client::HostInfo host = Host();
    const std::vector<tailgate::control::client::MapEndpoint> endpoints{
        tailgate::control::client::MapEndpoint{.AddressPort = "192.0.2.10:41641",
                                               .Type =
                                                   tailgate::control::client::EndpointType::Local}};

    const auto bytes = tailgate::control::client::ControlRequest::BuildMap(
        "nodekey:test", "discokey:test", host, 0, false, false, endpoints);
    const std::string request(bytes.begin(), bytes.end());

    EXPECT_TRUE(request.find("\"Endpoints\":[\"192.0.2.10:41641\"]") != std::string::npos);
    EXPECT_TRUE(request.find("\"EndpointTypes\":[1]") != std::string::npos);
}

TEST(Given_ControlRequests, When_FeatureQueryAndBuilding_Then_FeatureAndNodeKeyAreSent)
{
    const auto bytes =
        tailgate::control::client::ControlRequest::BuildQueryFeature("nodekey:test", "funnel");
    const std::string request(bytes.begin(), bytes.end());

    EXPECT_TRUE(request.find("\"Feature\":\"funnel\"") != std::string::npos);
    EXPECT_TRUE(request.find("\"NodeKey\":\"nodekey:test\"") != std::string::npos);
}

TEST(Given_ControlRequests, When_DnsChallengeAndBuildingRequest_Then_CurrentCapabilityAndTxtAreSent)
{
    const std::vector<std::uint8_t> encoded =
        tailgate::control::client::ControlRequest::BuildSetDns(
            "nodekey:abc", "_acme-challenge.node.ts.net", "txt");

    const std::string request(encoded.begin(), encoded.end());

    EXPECT_NE(request.find("\"Version\":141"), std::string::npos);
    EXPECT_NE(request.find("\"NodeKey\":\"nodekey:abc\""), std::string::npos);
    EXPECT_NE(request.find("\"Name\":\"_acme-challenge.node.ts.net\""), std::string::npos);
    EXPECT_NE(request.find("\"Type\":\"TXT\""), std::string::npos);
    EXPECT_NE(request.find("\"Value\":\"txt\""), std::string::npos);
}
