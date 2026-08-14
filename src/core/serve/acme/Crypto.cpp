#include <tailgate/serve/acme/Client.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <format>
#include <stdexcept>

#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <nlohmann/json.hpp>
#include <psa/crypto.h>

#include <tailgate/crypto/Base64.h>

#include "crypto/PsaCryptoContext.h"

namespace tailgate::serve::acme
{
namespace
{

constexpr std::size_t PrivateKeyBytes = 32;
constexpr std::size_t PublicKeyBytes = 65;
constexpr std::size_t CoordinateBytes = 32;

std::string Base64Url(const std::vector<std::uint8_t>& bytes)
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

void Check(psa_status_t status, const char* operation)
{
    if (status != PSA_SUCCESS)
    {
        throw std::runtime_error(std::format("{} failed: {}.", operation, status));
    }
}

class Key
{
public:
    explicit Key(const std::string& encoded)
    {
        const auto raw = tailgate::crypto::Base64Decode(encoded);
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&attributes, 256);
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
        psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
        Check(psa_import_key(&attributes, raw.data(), raw.size(), &Id), "ACME key import");
        psa_reset_key_attributes(&attributes);
    }

    ~Key()
    {
        if (!mbedtls_svc_key_id_is_null(Id))
        {
            (void)psa_destroy_key(Id);
        }
    }

    mbedtls_svc_key_id_t Id = MBEDTLS_SVC_KEY_ID_INIT;
};

std::vector<std::uint8_t> Public(Key& key)
{
    std::vector<std::uint8_t> bytes(PublicKeyBytes);
    std::size_t size = 0;
    Check(psa_export_public_key(key.Id, bytes.data(), bytes.size(), &size),
          "ACME public key export");
    bytes.resize(size);
    return bytes;
}

} // namespace

MbedTlsCrypto::MbedTlsCrypto()
    : m_context(std::make_unique<tailgate::crypto::detail::PsaCryptoContext>())
{
}

MbedTlsCrypto::~MbedTlsCrypto() = default;

std::string MbedTlsCrypto::GeneratePrivateKey()
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    mbedtls_svc_key_id_t id = MBEDTLS_SVC_KEY_ID_INIT;
    Check(psa_generate_key(&attributes, &id), "ACME key generation");
    psa_reset_key_attributes(&attributes);
    std::array<std::uint8_t, PrivateKeyBytes> raw{};
    std::size_t size = 0;
    const psa_status_t exported = psa_export_key(id, raw.data(), raw.size(), &size);
    (void)psa_destroy_key(id);
    Check(exported, "ACME private key export");
    return tailgate::crypto::Base64Encode(
        {raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(size)});
}

std::string MbedTlsCrypto::Jwk(const std::string& privateKey)
{
    Key key(privateKey);
    const auto publicKey = Public(key);
    if (publicKey.size() != PublicKeyBytes || publicKey[0] != 4)
    {
        throw std::runtime_error("Invalid P-256 public key.");
    }
    return nlohmann::json(
               {{"crv", "P-256"},
                {"kty", "EC"},
                {"x", Base64Url({publicKey.begin() + 1, publicKey.begin() + 1 + CoordinateBytes})},
                {"y", Base64Url({publicKey.begin() + 1 + CoordinateBytes, publicKey.end()})}})
        .dump();
}

std::vector<std::uint8_t> MbedTlsCrypto::Sign(const std::string& privateKey,
                                              const std::string& message)
{
    Key key(privateKey);
    std::array<std::uint8_t, 32> digest{};
    std::size_t digestSize = 0;
    Check(psa_hash_compute(PSA_ALG_SHA_256,
                           reinterpret_cast<const unsigned char*>(message.data()),
                           message.size(),
                           digest.data(),
                           digest.size(),
                           &digestSize),
          "ACME signing hash");
    std::vector<std::uint8_t> signature(64);
    std::size_t size = 0;
    Check(psa_sign_hash(key.Id,
                        PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                        digest.data(),
                        digest.size(),
                        signature.data(),
                        signature.size(),
                        &size),
          "ACME signing");
    signature.resize(size);
    return signature;
}

std::string MbedTlsCrypto::Thumbprint(const std::string& privateKey)
{
    const std::string jwk = Jwk(privateKey);
    std::array<std::uint8_t, 32> digest{};
    std::size_t digestSize = 0;
    Check(psa_hash_compute(PSA_ALG_SHA_256,
                           reinterpret_cast<const unsigned char*>(jwk.data()),
                           jwk.size(),
                           digest.data(),
                           digest.size(),
                           &digestSize),
          "ACME thumbprint hash");
    return Base64Url({digest.begin(), digest.end()});
}

std::vector<std::uint8_t> MbedTlsCrypto::CreateCertificateRequest(const std::string& privateKey,
                                                                  const std::string& domain)
{
    Key key(privateKey);
    mbedtls_pk_context pk{};
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_wrap_psa(&pk, key.Id) != 0)
    {
        throw std::runtime_error("ACME CSR key wrapping failed.");
    }
    mbedtls_x509write_csr request{};
    mbedtls_x509write_csr_init(&request);
    mbedtls_x509write_csr_set_md_alg(&request, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key(&request, &pk);
    const std::string subject = std::format("CN={}", domain);
    if (mbedtls_x509write_csr_set_subject_name(&request, subject.c_str()) != 0)
    {
        throw std::runtime_error("ACME CSR subject failed.");
    }
    mbedtls_x509_san_list san{};
    san.node.type = MBEDTLS_X509_SAN_DNS_NAME;
    san.node.san.unstructured_name.p =
        reinterpret_cast<unsigned char*>(const_cast<char*>(domain.data()));
    san.node.san.unstructured_name.len = domain.size();
    if (mbedtls_x509write_csr_set_subject_alternative_name(&request, &san) != 0)
    {
        throw std::runtime_error("ACME CSR SAN failed.");
    }
    std::vector<std::uint8_t> buffer(4096);
    const int size = mbedtls_x509write_csr_der(&request, buffer.data(), buffer.size());
    mbedtls_x509write_csr_free(&request);
    mbedtls_pk_free(&pk);
    if (size < 0)
    {
        throw std::runtime_error("ACME CSR encoding failed.");
    }
    return {buffer.end() - size, buffer.end()};
}

std::string MbedTlsCrypto::ToPem(const std::string& privateKey)
{
    Key key(privateKey);
    mbedtls_pk_context pk{};
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_wrap_psa(&pk, key.Id) != 0)
    {
        throw std::runtime_error("ACME PEM key wrapping failed.");
    }
    std::vector<unsigned char> buffer(4096);
    const int result = mbedtls_pk_write_key_pem(&pk, buffer.data(), buffer.size());
    mbedtls_pk_free(&pk);
    if (result != 0)
    {
        throw std::runtime_error("ACME private key PEM encoding failed.");
    }
    return reinterpret_cast<const char*>(buffer.data());
}

bool MbedTlsCrypto::CertificateValidFor(const std::string& certificatePem,
                                        std::chrono::hours minimumValidity) const
{
    mbedtls_x509_crt certificate{};
    mbedtls_x509_crt_init(&certificate);
    const int parsed =
        mbedtls_x509_crt_parse(&certificate,
                               reinterpret_cast<const unsigned char*>(certificatePem.c_str()),
                               certificatePem.size() + 1U);
    if (parsed != 0)
    {
        mbedtls_x509_crt_free(&certificate);
        return false;
    }
    using namespace std::chrono;
    const auto expiry = sys_days{year{certificate.valid_to.year} /
                                 month{static_cast<unsigned>(certificate.valid_to.mon)} /
                                 day{static_cast<unsigned>(certificate.valid_to.day)}} +
                        hours{certificate.valid_to.hour} + minutes{certificate.valid_to.min} +
                        seconds{certificate.valid_to.sec};
    mbedtls_x509_crt_free(&certificate);
    return expiry > system_clock::now() + minimumValidity;
}

} // namespace tailgate::serve::acme
