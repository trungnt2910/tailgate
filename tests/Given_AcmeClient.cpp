#include "tailgate/acme/AcmeClient.h"
#include <deque>
#include <gtest/gtest.h>

namespace
{

using namespace tailgate::acme;

class Http final : public IHttpClient
{
public:
    HttpResponse Send(const HttpRequest& request) override
    {
        Requests.push_back(request);
        if (Responses.empty())
        {
            throw std::runtime_error("unexpected HTTP request");
        }
        auto response = Responses.front();
        Responses.pop_front();
        return response;
    }

    std::deque<HttpResponse> Responses;
    std::vector<HttpRequest> Requests;
};

class Crypto final : public ICrypto
{
public:
    std::string GeneratePrivateKey() override
    {
        return ++Generated == 1 ? "account-key" : "cert-key";
    }

    std::string Jwk(const std::string&) override
    {
        return R"({"crv":"P-256","kty":"EC","x":"x","y":"y"})";
    }

    std::vector<std::uint8_t> Sign(const std::string&, const std::string&) override
    {
        return {1, 2};
    }

    std::string Thumbprint(const std::string&) override
    {
        return "thumbprint";
    }

    std::vector<std::uint8_t> CreateCertificateRequest(const std::string&,
                                                       const std::string&) override
    {
        return {3, 4};
    }

    std::string ToPem(const std::string&) override
    {
        return "PRIVATE KEY";
    }

    int Generated = 0;
};

class Publisher final : public IChallengePublisher
{
public:
    void PublishDnsTxt(const std::string& name, const std::string& value) override
    {
        Name = name;
        Value = value;
    }

    std::string Name, Value;
};

class Waiter final : public IWaiter
{
public:
    void Wait(std::chrono::seconds) override
    {
        ++Calls;
    }

    int Calls = 0;
};

HttpResponse Response(int status, std::string body, std::map<std::string, std::string> headers = {})
{
    headers.emplace("replay-nonce", "next-nonce");
    return {status, std::move(headers), std::move(body)};
}

} // namespace

TEST(Given_AcmeClient, When_DnsAuthorizationSucceeds_Then_ItReturnsIssuedCertificate)
{
    Http http;
    http.Responses = {
        Response(
            200,
            R"({"newNonce":"https://ca/nonce","newAccount":"https://ca/account","newOrder":"https://ca/order"})"),
        Response(204, ""),
        Response(201, R"({"status":"valid"})", {{"location", "https://ca/account/1"}}),
        Response(201,
                 R"({"authorizations":["https://ca/auth/1"],"finalize":"https://ca/finalize/1"})",
                 {{"location", "https://ca/order/1"}}),
        Response(
            200,
            R"({"challenges":[{"type":"dns-01","token":"token","url":"https://ca/challenge/1"}]})"),
        Response(200, R"({"status":"pending"})"),
        Response(200, R"({"status":"valid"})"),
        Response(200, R"({"status":"processing"})"),
        Response(200, R"({"status":"valid","certificate":"https://ca/cert/1"})"),
        Response(200, "CERTIFICATE"),
    };
    Crypto crypto;
    Publisher publisher;
    Waiter waiter;
    AcmeClient client(http, crypto, publisher, waiter, "https://ca/directory");

    const Certificate result = client.Issue("node.example.test");

    EXPECT_EQ(result.CertificatePem, "CERTIFICATE");
    EXPECT_EQ(result.PrivateKeyPem, "PRIVATE KEY");
    EXPECT_EQ(client.AccountPrivateKey(), "account-key");
    EXPECT_EQ(publisher.Name, "_acme-challenge.node.example.test");
    EXPECT_FALSE(publisher.Value.empty());
    EXPECT_EQ(waiter.Calls, 0);
    EXPECT_EQ(http.Requests.size(), 10U);
    EXPECT_EQ(http.Requests[0].Method, "GET");
    EXPECT_EQ(http.Requests[5].Url, "https://ca/challenge/1");
    EXPECT_EQ(http.Requests[9].Url, "https://ca/cert/1");
}
