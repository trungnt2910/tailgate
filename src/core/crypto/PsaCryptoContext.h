#pragma once

namespace tailgate::crypto::detail
{

class PsaCryptoContext final
{
public:
    PsaCryptoContext();
    ~PsaCryptoContext();
    PsaCryptoContext(const PsaCryptoContext&) = delete;
    PsaCryptoContext& operator=(const PsaCryptoContext&) = delete;
    PsaCryptoContext(PsaCryptoContext&&) = delete;
    PsaCryptoContext& operator=(PsaCryptoContext&&) = delete;
};

} // namespace tailgate::crypto::detail
