#include "PsaCryptoContext.h"

#include <cassert>
#include <cstddef>
#include <format>
#include <mutex>
#include <stdexcept>
#include <string>

#include <psa/crypto.h>
#include <psa/crypto_extra.h>

namespace tailgate::crypto::detail
{
namespace
{

std::mutex ContextMutex;
std::size_t ContextReferences = 0;

} // namespace

PsaCryptoContext::PsaCryptoContext()
{
    const std::lock_guard lock(ContextMutex);
    if (ContextReferences == 0)
    {
        const psa_status_t status = psa_crypto_init();
        if (status != PSA_SUCCESS)
        {
            throw std::runtime_error(std::format("PSA Crypto initialization failed: {}.", status));
        }
    }
    ++ContextReferences;
}

PsaCryptoContext::~PsaCryptoContext()
{
    const std::lock_guard lock(ContextMutex);
    assert(ContextReferences != 0);
    --ContextReferences;
    if (ContextReferences == 0)
    {
        mbedtls_psa_crypto_free();
    }
}

} // namespace tailgate::crypto::detail
