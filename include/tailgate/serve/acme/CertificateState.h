#pragma once

#include <string>

namespace tailgate::serve::acme
{

struct CertificateState
{
    std::string Domain;
    std::string AccountPrivateKey;
    std::string CertificatePem;
    std::string PrivateKeyPem;
};

} // namespace tailgate::serve::acme
