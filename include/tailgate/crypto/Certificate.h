#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <tailgate/crypto/Crypto.h>

namespace tailgate::crypto
{

class Certificate
{
public:
    virtual ~Certificate() = default;

    [[nodiscard]] virtual std::string GeneratePrivateKey() = 0;
    [[nodiscard]] virtual std::string Jwk(const std::string& privateKey) = 0;
    [[nodiscard]] virtual std::vector<std::uint8_t> Sign(const std::string& privateKey,
                                                         const std::string& input) = 0;
    [[nodiscard]] virtual std::string Thumbprint(const std::string& privateKey) = 0;
    [[nodiscard]] virtual Bytes32 Sha256(std::string_view input) = 0;
    [[nodiscard]] virtual std::vector<std::uint8_t>
    CreateCertificateRequest(const std::string& privateKey, const std::string& domain) = 0;
    [[nodiscard]] virtual std::string ToPem(const std::string& privateKey) = 0;
    [[nodiscard]] virtual bool CertificateValidFor(const std::string& certificatePem,
                                                   std::chrono::hours minimumValidity) const = 0;

protected:
    Certificate() = default;
};

} // namespace tailgate::crypto
