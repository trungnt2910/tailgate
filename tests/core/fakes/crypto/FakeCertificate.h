#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <tailgate/crypto/Certificate.h>

namespace tailgate::tests::fakes
{

class FakeCertificate final : public tailgate::crypto::Certificate
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

    tailgate::crypto::Bytes32 Sha256(std::string_view) override
    {
        tailgate::crypto::Bytes32 result{};
        result[0] = 1;
        return result;
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

    bool CertificateValidFor(const std::string&, std::chrono::hours) const override
    {
        return true;
    }

    int Generated{};
};

} // namespace tailgate::tests::fakes
