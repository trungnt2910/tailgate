#include <string>

#include <gtest/gtest.h>

#include <tailgate/net/http/Client.h>

TEST(Given_Request, When_HttpsRequestIsEncoded_Then_TargetAndHeadersArePreserved)
{
    const tailgate::net::http::Request request("POST",
                                               "https://acme.example.com:8443/order/1",
                                               {{"content-type", "application/json"}},
                                               "{}");

    const tailgate::net::http::HttpsUrl url = tailgate::net::http::HttpsUrl::Parse(request.Url());
    const std::string encoded = request.Encode();

    EXPECT_EQ(url.Host(), "acme.example.com");
    EXPECT_EQ(url.Service(), "8443");
    EXPECT_EQ(url.Path(), "/order/1");
    EXPECT_NE(encoded.find("POST /order/1 HTTP/1.1\r\n"), std::string::npos);
    EXPECT_NE(encoded.find("Host: acme.example.com:8443\r\n"), std::string::npos);
    EXPECT_NE(encoded.find("content-type: application/json\r\n"), std::string::npos);
    EXPECT_TRUE(encoded.ends_with("\r\n\r\n{}"));
}
