#include <gtest/gtest.h>

#include <tailgate/net/http/Client.h>
#include <tailgate/serve/acme/Client.h>

#include "fakes/crypto/FakeCertificate.h"
#include "fakes/net/http/FakeClient.h"
#include "fakes/serve/acme/FakeChallengePublisher.h"

namespace
{

using namespace tailgate::serve::acme;

using tailgate::tests::fakes::FakeCertificate;
using tailgate::tests::fakes::FakeChallengePublisher;
using tailgate::tests::fakes::net::http::FakeClient;

tailgate::net::http::Response
Response(int status, std::string body, std::map<std::string, std::string> headers = {})
{
    headers.emplace("replay-nonce", "next-nonce");
    return tailgate::net::http::Response(status, std::move(headers), std::move(body));
}

} // namespace

TEST(Given_AcmeClient, When_DnsAuthorizationSucceeds_Then_ItReturnsIssuedCertificate)
{
    FakeClient http;
    http.Responses = {
        Response(200,
                 R"({
                "newNonce":"https://ca.example.com/nonce",
                "newAccount":"https://ca.example.com/account",
                "newOrder":"https://ca.example.com/order"
            })"),
        Response(204, ""),
        Response(201, R"({"status":"valid"})", {{"location", "https://ca.example.com/account/1"}}),
        Response(201,
                 R"({
                "authorizations":["https://ca.example.com/auth/1"],
                "finalize":"https://ca.example.com/finalize/1"
            })",
                 {{"location", "https://ca.example.com/order/1"}}),
        Response(200,
                 R"({
                "challenges":[{
                    "type":"dns-01",
                    "token":"token",
                    "url":"https://ca.example.com/challenge/1"
                }]
            })"),
        Response(200, R"({"status":"pending"})"),
        Response(200, R"({"status":"valid"})"),
        Response(200, R"({"status":"processing"})"),
        Response(200, R"({"status":"valid","certificate":"https://ca.example.com/cert/1"})"),
        Response(200, "CERTIFICATE"),
    };
    FakeCertificate crypto;
    FakeChallengePublisher publisher;
    AcmeClient client(
        http, crypto, publisher, "https://ca.example.com/directory", std::chrono::seconds::zero());

    const Certificate result = client.Issue("node.example.com");

    EXPECT_EQ(result.CertificatePem, "CERTIFICATE");
    EXPECT_EQ(result.PrivateKeyPem, "PRIVATE KEY");
    EXPECT_EQ(client.AccountPrivateKey(), "account-key");
    EXPECT_EQ(publisher.Name, "_acme-challenge.node.example.com");
    EXPECT_FALSE(publisher.Value.empty());
    EXPECT_EQ(http.Requests.size(), 10U);
    EXPECT_EQ(http.Requests[0].Method(), "GET");
    EXPECT_EQ(http.Requests[5].Url(), "https://ca.example.com/challenge/1");
    EXPECT_EQ(http.Requests[9].Url(), "https://ca.example.com/cert/1");
}
