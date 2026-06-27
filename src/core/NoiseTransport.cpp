#include "tailgate/protocol/NoiseTransport.h"

#include "tailgate/protocol/Crypto.h"

#include <stdexcept>

namespace tailgate::protocol
{
namespace
{

constexpr std::uint8_t TransportFrameType = 0x04;
constexpr std::size_t TransportHeaderSize = 3;
constexpr std::size_t MaximumCiphertextSize = 0xffff;

} // namespace

NoiseTransport::NoiseTransport(IByteStream& stream, NoiseKeys keys) : m_stream(stream), m_keys(keys)
{
}

void NoiseTransport::Send(const std::vector<std::uint8_t>& plaintext)
{
    std::vector<std::uint8_t> ciphertext =
        ChaCha20Poly1305EncryptBigNonce(m_keys.TxKey, m_txNonce, {}, plaintext);
    ++m_txNonce;

    if (ciphertext.size() > MaximumCiphertextSize)
    {
        throw std::runtime_error("Noise transport frame is too large");
    }

    std::vector<std::uint8_t> frame;
    frame.reserve(TransportHeaderSize + ciphertext.size());
    frame.push_back(TransportFrameType);
    frame.push_back(static_cast<std::uint8_t>((ciphertext.size() >> 8) & 0xff));
    frame.push_back(static_cast<std::uint8_t>(ciphertext.size() & 0xff));
    frame.insert(frame.end(), ciphertext.begin(), ciphertext.end());
    m_sendBuffer.insert(m_sendBuffer.end(), frame.begin(), frame.end());
    Flush();
}

void NoiseTransport::Flush()
{
    while (m_sendOffset < m_sendBuffer.size())
    {
        const std::optional<std::size_t> written = m_stream.TryWriteSome(
            m_sendBuffer.data() + m_sendOffset, m_sendBuffer.size() - m_sendOffset);
        if (!written)
        {
            return;
        }
        if (*written == 0)
        {
            throw std::runtime_error("Noise transport stream closed during write");
        }
        m_sendOffset += *written;
    }
    m_sendBuffer.clear();
    m_sendOffset = 0;
}

bool NoiseTransport::HasPendingOutput() const
{
    return m_sendOffset < m_sendBuffer.size();
}

std::vector<std::uint8_t> NoiseTransport::Receive()
{
    std::vector<std::uint8_t> header = m_stream.ReadExact(TransportHeaderSize);
    if (header[0] != TransportFrameType)
    {
        throw std::runtime_error("unexpected Noise transport frame type");
    }

    std::size_t ciphertextLength = (static_cast<std::size_t>(header[1]) << 8) | header[2];
    std::vector<std::uint8_t> ciphertext = m_stream.ReadExact(ciphertextLength);
    std::vector<std::uint8_t> plaintext =
        ChaCha20Poly1305DecryptBigNonce(m_keys.RxKey, m_rxNonce, {}, ciphertext);
    ++m_rxNonce;
    return plaintext;
}

std::optional<std::vector<std::uint8_t>> NoiseTransport::TryReceive()
{
    auto completeFrameSize = [&]() -> std::optional<std::size_t>
    {
        if (m_receiveBuffer.size() < TransportHeaderSize)
        {
            return std::nullopt;
        }
        if (m_receiveBuffer[0] != TransportFrameType)
        {
            throw std::runtime_error("unexpected Noise transport frame type");
        }
        const std::size_t ciphertextLength =
            (static_cast<std::size_t>(m_receiveBuffer[1]) << 8) | m_receiveBuffer[2];
        return TransportHeaderSize + ciphertextLength;
    };

    std::optional<std::size_t> frameSize = completeFrameSize();
    if (!frameSize || m_receiveBuffer.size() < *frameSize)
    {
        const std::size_t availableCapacity =
            MaximumCiphertextSize + TransportHeaderSize - m_receiveBuffer.size();
        std::optional<std::vector<std::uint8_t>> available =
            m_stream.TryReadSome(availableCapacity);
        if (!available)
        {
            return std::nullopt;
        }
        if (available->empty())
        {
            throw std::runtime_error("Noise transport stream closed");
        }
        m_receiveBuffer.insert(m_receiveBuffer.end(), available->begin(), available->end());
        frameSize = completeFrameSize();
    }
    if (!frameSize || m_receiveBuffer.size() < *frameSize)
    {
        return std::nullopt;
    }

    std::vector<std::uint8_t> ciphertext(
        m_receiveBuffer.begin() + static_cast<std::ptrdiff_t>(TransportHeaderSize),
        m_receiveBuffer.begin() + static_cast<std::ptrdiff_t>(*frameSize));
    m_receiveBuffer.erase(m_receiveBuffer.begin(),
                          m_receiveBuffer.begin() + static_cast<std::ptrdiff_t>(*frameSize));
    std::vector<std::uint8_t> plaintext =
        ChaCha20Poly1305DecryptBigNonce(m_keys.RxKey, m_rxNonce, {}, ciphertext);
    ++m_rxNonce;
    return plaintext;
}

} // namespace tailgate::protocol
