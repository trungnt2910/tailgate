#include "tailgate/serve/acme/Client.h"

#include <algorithm>
#include <format>
#include <stdexcept>
#include <thread>

#include <nlohmann/json.hpp>

#include <tailgate/crypto/Base64.h>
#include <tailgate/crypto/Crypto.h>

namespace tailgate::serve::acme
{
namespace
{

constexpr int MaximumPollAttempts = 60;

std::string B64(const std::vector<std::uint8_t>& bytes)
{
    std::string text = tailgate::crypto::Base64Encode(bytes);
    std::replace(text.begin(), text.end(), '+', '-');
    std::replace(text.begin(), text.end(), '/', '_');
    while (!text.empty() && text.back() == '=')
    {
        text.pop_back();
    }
    return text;
}

std::string B64(const std::string& text)
{
    return B64(std::vector<std::uint8_t>(text.begin(), text.end()));
}

std::string Header(const tailgate::net::http::Response& response, const std::string& name)
{
    const auto found = response.Headers().find(name);
    if (found == response.Headers().end())
    {
        throw std::runtime_error(std::format("ACME response is missing {}.", name));
    }
    return found->second;
}

void Require(const tailgate::net::http::Response& response, std::initializer_list<int> statuses)
{
    if (std::find(statuses.begin(), statuses.end(), response.Status()) == statuses.end())
    {
        throw std::runtime_error(
            std::format("ACME HTTP {}: {}.", response.Status(), response.Body()));
    }
}

nlohmann::json Json(const tailgate::net::http::Response& response)
{
    auto json = nlohmann::json::parse(response.Body(), nullptr, false);
    if (json.is_discarded())
    {
        throw std::runtime_error("ACME response is not JSON.");
    }
    return json;
}

} // namespace

class AcmeClient::Impl
{
public:
    Impl(tailgate::net::http::Client& h,
         tailgate::crypto::Certificate& c,
         ChallengePublisher& p,
         std::string d,
         std::chrono::seconds pollInterval)
        : Http(h),
          CryptoProvider(c),
          Publisher(p),
          Directory(std::move(d)),
          PollInterval(pollInterval)
    {
    }

    tailgate::net::http::Response
    Signed(const std::string& url, const nlohmann::json& payload, bool jwk)
    {
        if (Nonce.empty())
        {
            auto response = Http.Send({"HEAD", NewNonce, {}, {}});
            Require(response, {200, 204});
            Nonce = Header(response, "replay-nonce");
        }
        nlohmann::json protectedValue = {{"alg", "ES256"}, {"nonce", Nonce}, {"url", url}};
        if (jwk)
        {
            protectedValue["jwk"] = nlohmann::json::parse(CryptoProvider.Jwk(AccountKey));
        }
        else
        {
            protectedValue["kid"] = AccountUrl;
        }
        const std::string protectedText = B64(protectedValue.dump());
        const std::string payloadText = payload.is_null() ? "" : B64(payload.dump());
        const std::string input = protectedText + "." + payloadText;
        nlohmann::json body = {{"protected", protectedText},
                               {"payload", payloadText},
                               {"signature", B64(CryptoProvider.Sign(AccountKey, input))}};
        auto response =
            Http.Send({"POST", url, {{"content-type", "application/jose+json"}}, body.dump()});
        const auto nonce = response.Headers().find("replay-nonce");
        Nonce = nonce == response.Headers().end() ? "" : nonce->second;
        return response;
    }

    nlohmann::json Poll(const std::string& url, const std::string& wanted)
    {
        for (int attempt = 0; attempt < MaximumPollAttempts; ++attempt)
        {
            auto response = Signed(url, nullptr, false);
            Require(response, {200});
            auto json = Json(response);
            const std::string status = json.value("status", "");
            if (status == wanted)
            {
                return json;
            }
            if (status == "invalid")
            {
                throw std::runtime_error(std::format("ACME object invalid: {}.", response.Body()));
            }
            if (PollInterval > std::chrono::seconds::zero())
            {
                std::this_thread::sleep_for(PollInterval);
            }
        }
        throw std::runtime_error("ACME poll timed out.");
    }

    Certificate Issue(const std::string& domain, const std::optional<std::string>& key)
    {
        if (domain.empty())
        {
            throw std::invalid_argument("ACME domain is empty.");
        }
        AccountKey = key.value_or(CryptoProvider.GeneratePrivateKey());
        auto directoryResponse = Http.Send({"GET", Directory, {}, {}});
        Require(directoryResponse, {200});
        auto directory = Json(directoryResponse);
        NewNonce = directory.at("newNonce");
        auto account = Signed(directory.at("newAccount"), {{"termsOfServiceAgreed", true}}, true);
        Require(account, {200, 201});
        AccountUrl = Header(account, "location");
        nlohmann::json identifiers = nlohmann::json::array({{{"type", "dns"}, {"value", domain}}});
        auto order = Signed(directory.at("newOrder"), {{"identifiers", identifiers}}, false);
        Require(order, {201});
        const std::string orderUrl = Header(order, "location");
        auto orderJson = Json(order);
        const std::string authorizationUrl = orderJson.at("authorizations").at(0);
        auto authorization = Signed(authorizationUrl, nullptr, false);
        Require(authorization, {200});
        const nlohmann::json authorizationJson = Json(authorization);
        nlohmann::json challenge;
        for (const auto& item : authorizationJson.at("challenges"))
        {
            if (item.value("type", "") == "dns-01")
            {
                challenge = item;
                break;
            }
        }
        if (challenge.is_null())
        {
            throw std::runtime_error("ACME server did not offer dns-01.");
        }
        const std::string authorizationText = std::format("{}.{}",
                                                          challenge.at("token").get<std::string>(),
                                                          CryptoProvider.Thumbprint(AccountKey));
        const tailgate::crypto::Bytes32 digest = CryptoProvider.Sha256(authorizationText);
        Publisher.PublishDnsTxt(std::format("_acme-challenge.{}", domain),
                                B64(std::vector<std::uint8_t>(digest.begin(), digest.end())));
        auto accepted = Signed(challenge.at("url"), nlohmann::json::object(), false);
        Require(accepted, {200});
        (void)Poll(authorizationUrl, "valid");
        const std::string certificateKey = CryptoProvider.GeneratePrivateKey();
        auto finalized =
            Signed(orderJson.at("finalize"),
                   {{"csr", B64(CryptoProvider.CreateCertificateRequest(certificateKey, domain))}},
                   false);
        Require(finalized, {200});
        orderJson = Poll(orderUrl, "valid");
        auto certificate = Signed(orderJson.at("certificate"), nullptr, false);
        Require(certificate, {200});
        return Certificate{.CertificatePem = certificate.Body(),
                           .PrivateKeyPem = CryptoProvider.ToPem(certificateKey)};
    }

    tailgate::net::http::Client& Http;
    tailgate::crypto::Certificate& CryptoProvider;
    ChallengePublisher& Publisher;
    std::string Directory, AccountKey, AccountUrl, NewNonce, Nonce;
    std::chrono::seconds PollInterval;
};

AcmeClient::AcmeClient(tailgate::net::http::Client& h,
                       tailgate::crypto::Certificate& c,
                       ChallengePublisher& p,
                       std::string d,
                       std::chrono::seconds pollInterval)
    : m_impl(new Impl(h, c, p, std::move(d), pollInterval))
{
}

AcmeClient::~AcmeClient()
{
    delete m_impl;
}

Certificate AcmeClient::Issue(const std::string& domain, const std::optional<std::string>& key)
{
    return m_impl->Issue(domain, key);
}

const std::string& AcmeClient::AccountPrivateKey() const
{
    return m_impl->AccountKey;
}

} // namespace tailgate::serve::acme
