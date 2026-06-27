#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tailgate::protocol
{

using Bytes32 = std::array<std::uint8_t, 32>;

[[nodiscard]] Bytes32 GeneratePrivateKey();
[[nodiscard]] Bytes32 Blake2s256(const std::uint8_t* data, std::size_t length);
[[nodiscard]] Bytes32 Blake2s256(const std::vector<std::uint8_t>& data);
[[nodiscard]] Bytes32 HmacBlake2s256(const std::uint8_t* key,
                                     std::size_t keyLength,
                                     const std::uint8_t* data,
                                     std::size_t dataLength);
[[nodiscard]] Bytes32 X25519PublicFromPrivate(const Bytes32& privateKey);
[[nodiscard]] Bytes32 X25519Shared(const Bytes32& privateKey, const Bytes32& publicKey);

void ClampCurve25519Private(Bytes32& privateKey);

[[nodiscard]] std::vector<std::uint8_t>
ChaCha20Poly1305EncryptBigNonce(const Bytes32& key,
                                std::uint64_t nonce,
                                const std::vector<std::uint8_t>& additionalData,
                                const std::vector<std::uint8_t>& plaintext);

[[nodiscard]] std::vector<std::uint8_t>
ChaCha20Poly1305DecryptBigNonce(const Bytes32& key,
                                std::uint64_t nonce,
                                const std::vector<std::uint8_t>& additionalData,
                                const std::vector<std::uint8_t>& ciphertext);

[[nodiscard]] std::vector<std::uint8_t> HexToBytes(const std::string& text);
[[nodiscard]] std::string BytesToHex(const std::uint8_t* data, std::size_t length);

} // namespace tailgate::protocol
