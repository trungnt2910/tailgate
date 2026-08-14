#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include <tailgate/crypto/Crypto.h>

namespace tailgate::control::base
{

struct NoiseKeys
{
    tailgate::crypto::Bytes32 TxKey{};
    tailgate::crypto::Bytes32 RxKey{};
};

class NoiseInitiator
{
public:
    static constexpr std::uint16_t ProtocolVersion = 131;

    explicit NoiseInitiator(tailgate::crypto::Bytes32 machinePrivateKey);
    NoiseInitiator(tailgate::crypto::Bytes32 machinePrivateKey,
                   tailgate::crypto::Bytes32 ephemeralPrivateKey);

    [[nodiscard]] const tailgate::crypto::Bytes32& MachinePublicKey() const;
    [[nodiscard]] std::vector<std::uint8_t> WriteMessage1();
    [[nodiscard]] NoiseKeys ReadMessage2(const std::vector<std::uint8_t>& message);

private:
    void Initialize();
    void MixHash(const std::uint8_t* data, std::size_t length);
    [[nodiscard]] tailgate::crypto::Bytes32 MixKey(const tailgate::crypto::Bytes32& input);
    [[nodiscard]] static std::array<tailgate::crypto::Bytes32, 3>
    Hkdf(const tailgate::crypto::Bytes32& chainingKey,
         const std::uint8_t* input,
         std::size_t inputLength);

    tailgate::crypto::Bytes32 m_machinePrivateKey;
    tailgate::crypto::Bytes32 m_machinePublicKey;
    tailgate::crypto::Bytes32 m_ephemeralPrivateKey;
    tailgate::crypto::Bytes32 m_ephemeralPublicKey;
    tailgate::crypto::Bytes32 m_serverPublicKey;
    tailgate::crypto::Bytes32 m_hash;
    tailgate::crypto::Bytes32 m_chainingKey;
    bool m_initialized = false;
};

} // namespace tailgate::control::base
