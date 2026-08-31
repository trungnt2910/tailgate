#pragma once

#include <memory>

#include <tailgate/crypto/Certificate.h>

namespace tailgate::crypto::detail
{

class PsaCryptoContext;

}

namespace tailgate::crypto::impl
{

class MbedTlsCertificate final : public Certificate
{
public:
    MbedTlsCertificate();
    ~MbedTlsCertificate() override;
    MbedTlsCertificate(const MbedTlsCertificate&) = delete;
    MbedTlsCertificate& operator=(const MbedTlsCertificate&) = delete;
    MbedTlsCertificate(MbedTlsCertificate&&) = delete;
    MbedTlsCertificate& operator=(MbedTlsCertificate&&) = delete;

    [[nodiscard]] std::string GeneratePrivateKey() override;
    [[nodiscard]] std::string Jwk(const std::string& privateKey) override;
    [[nodiscard]] std::vector<std::uint8_t> Sign(const std::string& privateKey,
                                                 const std::string& input) override;
    [[nodiscard]] std::string Thumbprint(const std::string& privateKey) override;
    [[nodiscard]] Bytes32 Sha256(std::string_view input) override;
    [[nodiscard]] std::vector<std::uint8_t>
    CreateCertificateRequest(const std::string& privateKey, const std::string& domain) override;
    [[nodiscard]] std::string ToPem(const std::string& privateKey) override;
    [[nodiscard]] bool CertificateValidFor(const std::string& certificatePem,
                                           std::chrono::hours minimumValidity) const override;

private:
    std::unique_ptr<tailgate::crypto::detail::PsaCryptoContext> m_context;
};

} // namespace tailgate::crypto::impl
