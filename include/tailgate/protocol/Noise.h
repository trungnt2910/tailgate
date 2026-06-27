#pragma once

#include "tailgate/protocol/Crypto.h"

#include <array>
#include <cstdint>
#include <vector>

namespace tailgate::protocol
{

struct NoiseKeys
{
    Bytes32 TxKey{};
    Bytes32 RxKey{};
};

class NoiseInitiator
{
public:
    static constexpr std::uint16_t ProtocolVersion = 131;

    explicit NoiseInitiator(Bytes32 machinePrivateKey);
    NoiseInitiator(Bytes32 machinePrivateKey, Bytes32 ephemeralPrivateKey);

    [[nodiscard]] const Bytes32& MachinePublicKey() const;
    [[nodiscard]] std::vector<std::uint8_t> WriteMessage1();
    [[nodiscard]] NoiseKeys ReadMessage2(const std::vector<std::uint8_t>& message);

private:
    void Initialize();
    void MixHash(const std::uint8_t* data, std::size_t length);
    [[nodiscard]] Bytes32 MixKey(const Bytes32& input);
    [[nodiscard]] static std::array<Bytes32, 3>
    Hkdf(const Bytes32& chainingKey, const std::uint8_t* input, std::size_t inputLength);

    Bytes32 m_machinePrivateKey;
    Bytes32 m_machinePublicKey;
    Bytes32 m_ephemeralPrivateKey;
    Bytes32 m_ephemeralPublicKey;
    Bytes32 m_serverPublicKey;
    Bytes32 m_hash;
    Bytes32 m_chainingKey;
    bool m_initialized = false;
};

} // namespace tailgate::protocol
