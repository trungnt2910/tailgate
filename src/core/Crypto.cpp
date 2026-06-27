#include "tailgate/protocol/Crypto.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

#include <sodium.h>

extern "C"
{
#include "crypto.h"
#include "crypto/refc/chacha20poly1305.h"
#include "crypto/refc/x25519.h"
}

namespace tailgate::protocol
{
namespace
{

constexpr std::size_t Blake2sBlockSize = 64;
constexpr std::uint8_t HmacInnerPadByte = 0x36;
constexpr std::uint8_t HmacOuterPadByte = 0x5c;
constexpr std::size_t ChaCha20Poly1305TagSize = 16;

std::uint64_t ByteSwap64(std::uint64_t value)
{
    return ((value & 0x00000000000000ffULL) << 56) | ((value & 0x000000000000ff00ULL) << 40) |
           ((value & 0x0000000000ff0000ULL) << 24) | ((value & 0x00000000ff000000ULL) << 8) |
           ((value & 0x000000ff00000000ULL) >> 8) | ((value & 0x0000ff0000000000ULL) >> 24) |
           ((value & 0x00ff000000000000ULL) >> 40) | ((value & 0xff00000000000000ULL) >> 56);
}

std::uint8_t HexNibble(char ch)
{
    if (ch >= '0' && ch <= '9')
    {
        return static_cast<std::uint8_t>(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f')
    {
        return static_cast<std::uint8_t>(10 + ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F')
    {
        return static_cast<std::uint8_t>(10 + ch - 'A');
    }
    throw std::runtime_error("invalid hex character");
}

} // namespace

Bytes32 GeneratePrivateKey()
{
    Bytes32 key{};
    randombytes_buf(key.data(), key.size());
    ClampCurve25519Private(key);
    return key;
}

Bytes32 Blake2s256(const std::uint8_t* data, std::size_t length)
{
    Bytes32 out{};
    blake2s(out.data(), out.size(), nullptr, 0, data, length);
    return out;
}

Bytes32 Blake2s256(const std::vector<std::uint8_t>& data)
{
    return Blake2s256(data.data(), data.size());
}

Bytes32 HmacBlake2s256(const std::uint8_t* key,
                       std::size_t keyLength,
                       const std::uint8_t* data,
                       std::size_t dataLength)
{
    std::array<std::uint8_t, Blake2sBlockSize> keyBlock{};
    if (keyLength > Blake2sBlockSize)
    {
        Bytes32 hashed = Blake2s256(key, keyLength);
        std::copy(hashed.begin(), hashed.end(), keyBlock.begin());
    }
    else if (keyLength > 0)
    {
        std::copy(key, key + keyLength, keyBlock.begin());
    }

    std::array<std::uint8_t, Blake2sBlockSize> innerPad{};
    std::array<std::uint8_t, Blake2sBlockSize> outerPad{};
    for (std::size_t index = 0; index < Blake2sBlockSize; ++index)
    {
        innerPad[index] = keyBlock[index] ^ HmacInnerPadByte;
        outerPad[index] = keyBlock[index] ^ HmacOuterPadByte;
    }

    blake2s_ctx ctx;
    Bytes32 innerHash{};
    blake2s_init(&ctx, innerHash.size(), nullptr, 0);
    blake2s_update(&ctx, innerPad.data(), innerPad.size());
    blake2s_update(&ctx, data, dataLength);
    blake2s_final(&ctx, innerHash.data());

    Bytes32 out{};
    blake2s_init(&ctx, out.size(), nullptr, 0);
    blake2s_update(&ctx, outerPad.data(), outerPad.size());
    blake2s_update(&ctx, innerHash.data(), innerHash.size());
    blake2s_final(&ctx, out.data());
    return out;
}

void ClampCurve25519Private(Bytes32& privateKey)
{
    privateKey[0] &= 248;
    privateKey[31] &= 127;
    privateKey[31] |= 64;
}

Bytes32 X25519PublicFromPrivate(const Bytes32& privateKey)
{
    Bytes32 out{};
    x25519_base(out.data(), privateKey.data(), 1);
    return out;
}

Bytes32 X25519Shared(const Bytes32& privateKey, const Bytes32& publicKey)
{
    Bytes32 out{};
    x25519(out.data(), privateKey.data(), publicKey.data(), 1);
    return out;
}

std::vector<std::uint8_t>
ChaCha20Poly1305EncryptBigNonce(const Bytes32& key,
                                std::uint64_t nonce,
                                const std::vector<std::uint8_t>& additionalData,
                                const std::vector<std::uint8_t>& plaintext)
{
    std::vector<std::uint8_t> ciphertext(plaintext.size() + ChaCha20Poly1305TagSize);
    chacha20poly1305_encrypt(ciphertext.data(),
                             plaintext.data(),
                             plaintext.size(),
                             additionalData.data(),
                             additionalData.size(),
                             ByteSwap64(nonce),
                             key.data());
    return ciphertext;
}

std::vector<std::uint8_t>
ChaCha20Poly1305DecryptBigNonce(const Bytes32& key,
                                std::uint64_t nonce,
                                const std::vector<std::uint8_t>& additionalData,
                                const std::vector<std::uint8_t>& ciphertext)
{
    if (ciphertext.size() < ChaCha20Poly1305TagSize)
    {
        throw std::runtime_error("ciphertext too short");
    }

    std::vector<std::uint8_t> plaintext(ciphertext.size() - ChaCha20Poly1305TagSize);
    bool ok = chacha20poly1305_decrypt(plaintext.data(),
                                       ciphertext.data(),
                                       ciphertext.size(),
                                       additionalData.data(),
                                       additionalData.size(),
                                       ByteSwap64(nonce),
                                       key.data());
    if (!ok)
    {
        throw std::runtime_error("chacha20-poly1305 authentication failed");
    }
    return plaintext;
}

std::vector<std::uint8_t> HexToBytes(const std::string& text)
{
    if (text.size() % 2 != 0)
    {
        throw std::runtime_error("hex string must contain an even number of characters");
    }

    std::vector<std::uint8_t> result(text.size() / 2);
    for (std::size_t index = 0; index < result.size(); ++index)
    {
        result[index] = static_cast<std::uint8_t>((HexNibble(text[index * 2]) << 4) |
                                                  HexNibble(text[index * 2 + 1]));
    }
    return result;
}

std::string BytesToHex(const std::uint8_t* data, std::size_t length)
{
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < length; ++index)
    {
        stream << std::setw(2) << static_cast<int>(data[index]);
    }
    return stream.str();
}

} // namespace tailgate::protocol
