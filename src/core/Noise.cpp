#include "tailgate/protocol/Noise.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>

namespace tailgate::protocol
{
namespace
{

constexpr std::array<std::uint8_t, 32> TailscaleServerPublicKey{
    0x7d, 0x27, 0x92, 0xf9, 0xc9, 0x8d, 0x75, 0x3d, 0x20, 0x42, 0x47, 0x15, 0x36, 0x80, 0x19, 0x49,
    0x10, 0x4c, 0x24, 0x7f, 0x95, 0xea, 0xc7, 0x70, 0xf8, 0xfb, 0x32, 0x15, 0x95, 0xe2, 0x17, 0x3b,
};

std::vector<std::uint8_t> ToVector(const Bytes32& bytes)
{
    return std::vector<std::uint8_t>(bytes.begin(), bytes.end());
}

} // namespace

NoiseInitiator::NoiseInitiator(Bytes32 machinePrivateKey) : m_machinePrivateKey(machinePrivateKey)
{
    // Callers that need deterministic handshakes should use the overload that supplies this key.
    throw std::runtime_error("Random ephemeral key generation is not wired yet.");
}

NoiseInitiator::NoiseInitiator(Bytes32 machinePrivateKey, Bytes32 ephemeralPrivateKey)
    : m_machinePrivateKey(machinePrivateKey), m_ephemeralPrivateKey(ephemeralPrivateKey)
{
    ClampCurve25519Private(m_machinePrivateKey);
    ClampCurve25519Private(m_ephemeralPrivateKey);
    m_machinePublicKey = X25519PublicFromPrivate(m_machinePrivateKey);
    m_ephemeralPublicKey = X25519PublicFromPrivate(m_ephemeralPrivateKey);
    m_serverPublicKey = TailscaleServerPublicKey;
    Initialize();
}

const Bytes32& NoiseInitiator::MachinePublicKey() const
{
    return m_machinePublicKey;
}

std::array<Bytes32, 3>
NoiseInitiator::Hkdf(const Bytes32& chainingKey, const std::uint8_t* input, std::size_t inputLength)
{
    Bytes32 tempKey = HmacBlake2s256(chainingKey.data(), chainingKey.size(), input, inputLength);

    const std::uint8_t one = 0x01;
    Bytes32 out1 = HmacBlake2s256(tempKey.data(), tempKey.size(), &one, 1);

    std::array<std::uint8_t, 33> out1WithCounter{};
    std::copy(out1.begin(), out1.end(), out1WithCounter.begin());
    out1WithCounter[32] = 0x02;
    Bytes32 out2 = HmacBlake2s256(
        tempKey.data(), tempKey.size(), out1WithCounter.data(), out1WithCounter.size());

    std::array<std::uint8_t, 33> out2WithCounter{};
    std::copy(out2.begin(), out2.end(), out2WithCounter.begin());
    out2WithCounter[32] = 0x03;
    Bytes32 out3 = HmacBlake2s256(
        tempKey.data(), tempKey.size(), out2WithCounter.data(), out2WithCounter.size());

    return {out1, out2, out3};
}

void NoiseInitiator::Initialize()
{
    const std::string protocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
    m_hash =
        Blake2s256(reinterpret_cast<const std::uint8_t*>(protocolName.data()), protocolName.size());
    m_chainingKey = m_hash;

    const std::string prologue = "Tailscale Control Protocol v131";
    MixHash(reinterpret_cast<const std::uint8_t*>(prologue.data()), prologue.size());
    MixHash(m_serverPublicKey.data(), m_serverPublicKey.size());
    m_initialized = true;
}

void NoiseInitiator::MixHash(const std::uint8_t* data, std::size_t length)
{
    std::vector<std::uint8_t> input;
    input.reserve(m_hash.size() + length);
    input.insert(input.end(), m_hash.begin(), m_hash.end());
    input.insert(input.end(), data, data + length);
    m_hash = Blake2s256(input);
}

Bytes32 NoiseInitiator::MixKey(const Bytes32& input)
{
    std::array<Bytes32, 3> result = Hkdf(m_chainingKey, input.data(), input.size());
    m_chainingKey = result[0];
    return result[1];
}

std::vector<std::uint8_t> NoiseInitiator::WriteMessage1()
{
    if (!m_initialized)
    {
        throw std::runtime_error("Noise initiator is not initialized.");
    }

    std::vector<std::uint8_t> out;
    out.reserve(101);
    out.push_back(static_cast<std::uint8_t>((ProtocolVersion >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(ProtocolVersion & 0xff));
    out.push_back(0x01);
    out.push_back(0x00);
    out.push_back(0x60);

    out.insert(out.end(), m_ephemeralPublicKey.begin(), m_ephemeralPublicKey.end());
    MixHash(m_ephemeralPublicKey.data(), m_ephemeralPublicKey.size());

    Bytes32 key = MixKey(X25519Shared(m_ephemeralPrivateKey, m_serverPublicKey));
    std::vector<std::uint8_t> encryptedStatic =
        ChaCha20Poly1305EncryptBigNonce(key, 0, ToVector(m_hash), ToVector(m_machinePublicKey));
    out.insert(out.end(), encryptedStatic.begin(), encryptedStatic.end());
    MixHash(encryptedStatic.data(), encryptedStatic.size());

    key = MixKey(X25519Shared(m_machinePrivateKey, m_serverPublicKey));
    std::vector<std::uint8_t> encryptedPayload =
        ChaCha20Poly1305EncryptBigNonce(key, 0, ToVector(m_hash), {});
    out.insert(out.end(), encryptedPayload.begin(), encryptedPayload.end());
    MixHash(encryptedPayload.data(), encryptedPayload.size());

    return out;
}

NoiseKeys NoiseInitiator::ReadMessage2(const std::vector<std::uint8_t>& message)
{
    if (message.size() < 48)
    {
        throw std::runtime_error("Noise message 2 is too short.");
    }

    Bytes32 remoteEphemeral{};
    std::copy(message.begin(), message.begin() + 32, remoteEphemeral.begin());
    MixHash(remoteEphemeral.data(), remoteEphemeral.size());

    (void)MixKey(X25519Shared(m_ephemeralPrivateKey, remoteEphemeral));
    Bytes32 key = MixKey(X25519Shared(m_machinePrivateKey, remoteEphemeral));

    std::vector<std::uint8_t> ciphertext(message.begin() + 32, message.end());
    (void)ChaCha20Poly1305DecryptBigNonce(key, 0, ToVector(m_hash), ciphertext);
    MixHash(ciphertext.data(), ciphertext.size());

    std::array<Bytes32, 3> split = Hkdf(m_chainingKey, nullptr, 0);
    return NoiseKeys{.TxKey = split[0], .RxKey = split[1]};
}

} // namespace tailgate::protocol
