#pragma once

#include <chrono>
#include <optional>
#include <string>

#include <tailgate/crypto/Certificate.h>
#include <tailgate/net/http/Client.h>

namespace tailgate::serve::acme
{

struct Certificate
{
    std::string CertificatePem;
    std::string PrivateKeyPem;
};

class ChallengePublisher
{
public:
    virtual ~ChallengePublisher() = default;
    virtual void PublishDnsTxt(const std::string&, const std::string&) = 0;
};

class AcmeClient final
{
public:
    static constexpr const char* LetsEncryptDirectory =
        "https://acme-v02.api.letsencrypt.org/directory";
    AcmeClient(tailgate::net::http::Client&,
               tailgate::crypto::Certificate&,
               ChallengePublisher&,
               std::string directoryUrl = LetsEncryptDirectory,
               std::chrono::seconds pollInterval = std::chrono::seconds(2));
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

} // namespace tailgate::serve::acme
