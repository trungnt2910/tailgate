#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/di/Bindings.h>
#include <tailgate/net/http/Client.h>
#include <tailgate/types/nettype/TcpSocket.h>

#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/types/nettype/FakeTcpSocket.h"

TEST(Given_HttpClient, When_SendingHttpsRequest_Then_TlsSocketAndResponseCodecAreUsed)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto state = std::make_shared<tailgate::tests::fakes::FakeTcpSocketState>();
    const std::string encodedResponse =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nReplay-Nonce: fake-nonce\r\n\r\n{}";
    state->Incoming.emplace_back(encodedResponse.begin(), encodedResponse.end());
    state->Incoming.emplace_back();
    std::optional<tailgate::types::nettype::TcpSocketOptions> openedOptions;
    auto& socketFactory = dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory&>(
        injector.create<tailgate::types::nettype::TcpSocketFactory&>());
    socketFactory.Open = [&](const tailgate::types::nettype::TcpSocketOptions& options)
    {
        openedOptions = options;
        return std::make_unique<tailgate::tests::fakes::FakeTcpSocket>(state);
    };
    tailgate::net::http::Client& client = injector.create<tailgate::net::http::Client&>();
    const tailgate::net::http::Request request("POST",
                                               "https://api.example.com:8443/order/1",
                                               {{"content-type", "application/json"}},
                                               "{}");

    const tailgate::net::http::Response response = client.Send(request);
    const std::string written(state->Written.begin(), state->Written.end());
    const std::string connectAddress = openedOptions ? openedOptions->ConnectAddress : "";
    const std::string service = openedOptions ? openedOptions->Service : "";
    const std::optional<std::string> tlsServerName =
        openedOptions ? openedOptions->TlsServerName : std::nullopt;
    const bool nonBlockingAfterConnect = openedOptions && openedOptions->NonBlockingAfterConnect;

    EXPECT_TRUE(openedOptions.has_value());
    EXPECT_EQ(connectAddress, "api.example.com");
    EXPECT_EQ(service, "8443");
    EXPECT_EQ(tlsServerName, "api.example.com");
    EXPECT_FALSE(nonBlockingAfterConnect);
    EXPECT_TRUE(written.starts_with("POST /order/1 HTTP/1.1\r\n"));
    EXPECT_EQ(response.Status(), 200);
    EXPECT_EQ(response.Headers().at("replay-nonce"), "fake-nonce");
    EXPECT_EQ(response.Body(), "{}");
}
