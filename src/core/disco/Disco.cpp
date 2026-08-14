#include <tailgate/disco/Disco.h>

#include <algorithm>
#include <cstring>

#include <sodium.h>

namespace tailgate::disco
{

using tailgate::crypto::Bytes32;
using tailgate::crypto::X25519PublicFromPrivate;

namespace
{

constexpr std::array<std::uint8_t, 6> Magic{0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac};
constexpr std::size_t HeaderSize = Magic.size() + 32;
constexpr std::uint8_t PingType = 0x01;
constexpr std::uint8_t PongType = 0x02;
constexpr std::uint8_t CallMeMaybeType = 0x03;
constexpr std::uint8_t ProtocolVersion = 0;
constexpr std::size_t EndpointSize = 18;
constexpr std::size_t MessageHeaderSize = 2;
constexpr std::size_t Ipv4MappedPrefixZeroBytes = 10;
constexpr std::size_t Ipv4MappedMarkerOffset = 10;
constexpr std::size_t Ipv4AddressOffset = 12;
constexpr std::size_t EndpointPortOffset = 16;

Bytes32 SharedKey(const Bytes32& privateKey, const Bytes32& publicKey)
{
    Bytes32 shared{};
    if (crypto_box_beforenm(shared.data(), publicKey.data(), privateKey.data()) != 0)
    {
        return {};
    }
    return shared;
}

} // namespace

Disco::Disco(const Bytes32& privateKey, const Bytes32& nodePublicKey)
    : Private(privateKey), Public(X25519PublicFromPrivate(privateKey)), NodePublic(nodePublicKey)
{
}

const Bytes32& Disco::PublicKey() const
{
    return Public;
}

Disco::TransactionId Disco::NewTransactionId() const
{
    TransactionId result{};
    randombytes_buf(result.data(), result.size());
    return result;
}

std::vector<std::uint8_t> Disco::BuildPing(const Bytes32& recipient,
                                           const TransactionId& transaction) const
{
    std::vector<std::uint8_t> message{PingType, ProtocolVersion};
    message.insert(message.end(), transaction.begin(), transaction.end());
    message.insert(message.end(), NodePublic.begin(), NodePublic.end());
    return Seal(recipient, message);
}

std::vector<std::uint8_t> Disco::BuildPong(const Bytes32& recipient,
                                           const TransactionId& transaction,
                                           std::uint32_t sourceAddress,
                                           std::uint16_t sourcePort) const
{
    std::vector<std::uint8_t> message{PongType, ProtocolVersion};
    message.insert(message.end(), transaction.begin(), transaction.end());
    message.insert(message.end(), Ipv4MappedPrefixZeroBytes, 0);
    message.insert(message.end(), Ipv4AddressOffset - Ipv4MappedPrefixZeroBytes, 0xff);
    message.push_back(static_cast<std::uint8_t>(sourceAddress >> 24U));
    message.push_back(static_cast<std::uint8_t>(sourceAddress >> 16U));
    message.push_back(static_cast<std::uint8_t>(sourceAddress >> 8U));
    message.push_back(static_cast<std::uint8_t>(sourceAddress));
    message.push_back(static_cast<std::uint8_t>(sourcePort >> 8U));
    message.push_back(static_cast<std::uint8_t>(sourcePort));
    return Seal(recipient, message);
}

std::vector<std::uint8_t> Disco::BuildCallMeMaybe(const Bytes32& recipient,
                                                  const std::vector<Endpoint>& endpoints) const
{
    std::vector<std::uint8_t> message{CallMeMaybeType, ProtocolVersion};
    for (const Endpoint& endpoint : endpoints)
    {
        message.insert(message.end(), Ipv4MappedPrefixZeroBytes, 0);
        message.push_back(0xff);
        message.push_back(0xff);
        message.push_back(static_cast<std::uint8_t>(endpoint.Address >> 24U));
        message.push_back(static_cast<std::uint8_t>(endpoint.Address >> 16U));
        message.push_back(static_cast<std::uint8_t>(endpoint.Address >> 8U));
        message.push_back(static_cast<std::uint8_t>(endpoint.Address));
        message.push_back(static_cast<std::uint8_t>(endpoint.Port >> 8U));
        message.push_back(static_cast<std::uint8_t>(endpoint.Port));
    }
    return Seal(recipient, message);
}

std::optional<Disco::Message> Disco::Parse(const std::vector<std::uint8_t>& packet) const
{
    constexpr std::size_t minimumPlaintextSize = MessageHeaderSize;
    if (!IsDiscoPacket(packet) || packet.size() < HeaderSize + crypto_box_NONCEBYTES +
                                                      crypto_box_MACBYTES + minimumPlaintextSize)
    {
        return std::nullopt;
    }
    Bytes32 sender{};
    std::copy_n(
        packet.begin() + static_cast<std::ptrdiff_t>(Magic.size()), sender.size(), sender.begin());
    const Bytes32 shared = SharedKey(Private, sender);
    const std::uint8_t* nonce = packet.data() + HeaderSize;
    const std::uint8_t* ciphertext = nonce + crypto_box_NONCEBYTES;
    const std::size_t ciphertextSize = packet.size() - HeaderSize - crypto_box_NONCEBYTES;
    std::vector<std::uint8_t> plaintext(ciphertextSize - crypto_box_MACBYTES);
    if (crypto_box_open_easy_afternm(
            plaintext.data(), ciphertext, ciphertextSize, nonce, shared.data()) != 0)
    {
        return std::nullopt;
    }
    if (plaintext[1] != ProtocolVersion)
    {
        return std::nullopt;
    }
    Message result;
    if (plaintext[0] == PingType || plaintext[0] == PongType)
    {
        if (plaintext.size() < MessageHeaderSize + result.Transaction.size())
        {
            return std::nullopt;
        }
        result.Type = plaintext[0] == PingType ? MessageType::Ping : MessageType::Pong;
        std::copy_n(plaintext.begin() + MessageHeaderSize,
                    result.Transaction.size(),
                    result.Transaction.begin());
    }
    else if (plaintext[0] == CallMeMaybeType)
    {
        if ((plaintext.size() - MessageHeaderSize) % EndpointSize != 0)
        {
            return std::nullopt;
        }
        result.Type = MessageType::CallMeMaybe;
        for (std::size_t offset = MessageHeaderSize; offset < plaintext.size();
             offset += EndpointSize)
        {
            const bool ipv4Mapped =
                std::all_of(plaintext.begin() + static_cast<std::ptrdiff_t>(offset),
                            plaintext.begin() +
                                static_cast<std::ptrdiff_t>(offset + Ipv4MappedPrefixZeroBytes),
                            [](std::uint8_t value)
                            {
                                return value == 0;
                            }) &&
                plaintext[offset + Ipv4MappedMarkerOffset] == 0xff &&
                plaintext[offset + Ipv4MappedMarkerOffset + 1] == 0xff;
            const std::uint16_t port =
                (static_cast<std::uint16_t>(plaintext[offset + EndpointPortOffset]) << 8U) |
                plaintext[offset + EndpointPortOffset + 1];
            if (ipv4Mapped && port != 0)
            {
                result.Endpoints.push_back(Endpoint{
                    .Address =
                        (static_cast<std::uint32_t>(plaintext[offset + Ipv4AddressOffset]) << 24U) |
                        (static_cast<std::uint32_t>(plaintext[offset + Ipv4AddressOffset + 1])
                         << 16U) |
                        (static_cast<std::uint32_t>(plaintext[offset + Ipv4AddressOffset + 2])
                         << 8U) |
                        plaintext[offset + Ipv4AddressOffset + 3],
                    .Port = port});
            }
        }
    }
    else
    {
        return std::nullopt;
    }
    result.Sender = sender;
    return result;
}

bool Disco::IsDiscoPacket(const std::vector<std::uint8_t>& packet)
{
    return packet.size() >= HeaderSize && std::equal(Magic.begin(), Magic.end(), packet.begin());
}

std::vector<std::uint8_t> Disco::Seal(const Bytes32& recipient,
                                      const std::vector<std::uint8_t>& message) const
{
    const Bytes32 shared = SharedKey(Private, recipient);
    std::vector<std::uint8_t> result;
    result.insert(result.end(), Magic.begin(), Magic.end());
    result.insert(result.end(), Public.begin(), Public.end());
    const std::size_t nonceOffset = result.size();
    result.resize(result.size() + crypto_box_NONCEBYTES);
    randombytes_buf(result.data() + nonceOffset, crypto_box_NONCEBYTES);
    const std::size_t cipherOffset = result.size();
    result.resize(result.size() + crypto_box_MACBYTES + message.size());
    crypto_box_easy_afternm(result.data() + cipherOffset,
                            message.data(),
                            message.size(),
                            result.data() + nonceOffset,
                            shared.data());
    return result;
}

} // namespace tailgate::disco
