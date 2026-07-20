#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace tailgate::detail
{

class PsaCryptoContext;

}

namespace tailgate::acme
{

struct HttpRequest
{
    std::string Method;
    std::string Url;
    std::map<std::string, std::string> Headers;
    std::string Body;
};

struct HttpResponse
{
    int Status = 0;
    std::map<std::string, std::string> Headers;
    std::string Body;
};

struct Certificate
{
    std::string CertificatePem;
    std::string PrivateKeyPem;
};

class IHttpClient
{
public:
    virtual ~IHttpClient() = default;
    [[nodiscard]] virtual HttpResponse Send(const HttpRequest&) = 0;
};

class ICrypto
{
public:
    virtual ~ICrypto() = default;
    [[nodiscard]] virtual std::string GeneratePrivateKey() = 0;
    [[nodiscard]] virtual std::string Jwk(const std::string&) = 0;
    [[nodiscard]] virtual std::vector<std::uint8_t> Sign(const std::string&,
                                                         const std::string&) = 0;
    [[nodiscard]] virtual std::string Thumbprint(const std::string&) = 0;
    [[nodiscard]] virtual std::vector<std::uint8_t>
    CreateCertificateRequest(const std::string&, const std::string&) = 0;
    [[nodiscard]] virtual std::string ToPem(const std::string&) = 0;
};

class IChallengePublisher
{
public:
    virtual ~IChallengePublisher() = default;
    virtual void PublishDnsTxt(const std::string&, const std::string&) = 0;
};

class IWaiter
{
public:
    virtual ~IWaiter() = default;
    virtual void Wait(std::chrono::seconds) = 0;
};

class AcmeClient final
{
public:
    static constexpr const char* LetsEncryptDirectory =
        "https://acme-v02.api.letsencrypt.org/directory";
    AcmeClient(IHttpClient&,
               ICrypto&,
               IChallengePublisher&,
               IWaiter&,
               std::string directoryUrl = LetsEncryptDirectory);
    ~AcmeClient();
    AcmeClient(const AcmeClient&) = delete;
    AcmeClient& operator=(const AcmeClient&) = delete;
    [[nodiscard]] Certificate Issue(const std::string&,
                                    const std::optional<std::string>& accountPrivateKey = {});
    [[nodiscard]] const std::string& AccountPrivateKey() const;

private:
    class Impl;
    Impl* m_impl;
};

class MbedTlsCrypto final : public ICrypto
{
public:
    MbedTlsCrypto();
    ~MbedTlsCrypto() override;
    MbedTlsCrypto(const MbedTlsCrypto&) = delete;
    MbedTlsCrypto& operator=(const MbedTlsCrypto&) = delete;
    MbedTlsCrypto(MbedTlsCrypto&&) = delete;
    MbedTlsCrypto& operator=(MbedTlsCrypto&&) = delete;
    [[nodiscard]] std::string GeneratePrivateKey() override;
    [[nodiscard]] std::string Jwk(const std::string&) override;
    [[nodiscard]] std::vector<std::uint8_t> Sign(const std::string&, const std::string&) override;
    [[nodiscard]] std::string Thumbprint(const std::string&) override;
    [[nodiscard]] std::vector<std::uint8_t> CreateCertificateRequest(const std::string&,
                                                                     const std::string&) override;
    [[nodiscard]] std::string ToPem(const std::string&) override;
    [[nodiscard]] bool CertificateValidFor(const std::string& certificatePem,
                                           std::chrono::hours minimumValidity) const;

private:
    std::unique_ptr<tailgate::detail::PsaCryptoContext> m_context;
};

} // namespace tailgate::acme
