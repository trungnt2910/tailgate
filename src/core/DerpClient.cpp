#include "tailgate/protocol/DerpClient.h"

#include "tailgate/Logging.h"
#include "tailgate/protocol/Crypto.h"

#include <algorithm>
#include <format>
#include <stdexcept>
#include <string>

#include <sodium.h>

namespace tailgate::protocol
{
namespace
{

constexpr std::uint8_t ServerKeyFrame = 0x01;
constexpr std::uint8_t ClientInfoFrame = 0x02;
constexpr std::uint8_t ServerInfoFrame = 0x03;
constexpr std::uint8_t SendPacketFrame = 0x04;
constexpr std::uint8_t ReceivePacketFrame = 0x05;
constexpr std::uint8_t KeepAliveFrame = 0x06;
constexpr std::uint8_t PreferredFrame = 0x07;
constexpr std::uint8_t PeerGoneFrame = 0x08;
constexpr std::uint8_t HealthFrame = 0x14;
constexpr std::uint8_t PingFrame = 0x12;
constexpr std::uint8_t PongFrame = 0x13;
constexpr std::size_t MaximumFrameSize = 1U << 20;
constexpr std::size_t FrameHeaderSize = 5;
constexpr std::size_t MaximumHttpHeaderSize = 8192;
constexpr std::size_t ServerGreetingSize = 40;
constexpr std::size_t MaximumReceiveBatchFrames = 256;
const std::array<std::uint8_t, 8> DerpMagic{'D', 'E', 'R', 'P', 0xf0, 0x9f, 0x94, 0x91};

} // namespace

DerpClient::DerpClient(IByteStream& stream, Key privateKey, Key publicKey)
    : Stream(stream), PrivateKey(privateKey), PublicKey(publicKey)
{
    if (sodium_init() < 0)
    {
        throw std::runtime_error("Libsodium initialization failed.");
    }
}

DerpClient::DerpClient(IByteStream& stream, Authenticator authenticator)
    : Stream(stream), Authenticate(std::move(authenticator))
{
    if (!Authenticate)
    {
        throw std::invalid_argument("DERP authenticator is empty.");
    }
    if (sodium_init() < 0)
    {
        throw std::runtime_error("Libsodium initialization failed.");
    }
}

std::vector<std::uint8_t>
DerpClient::BuildClientInfo(const Key& privateKey, const Key& publicKey, const Key& serverKey)
{
    static constexpr char ClientInfo[] = "{\"version\":2,\"CanAckPings\":true,\"IsProber\":false}";
    std::array<std::uint8_t, crypto_box_NONCEBYTES> nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    std::vector<std::uint8_t> ciphertext(sizeof(ClientInfo) - 1 + crypto_box_MACBYTES);
    if (crypto_box_easy(ciphertext.data(),
                        reinterpret_cast<const unsigned char*>(ClientInfo),
                        sizeof(ClientInfo) - 1,
                        nonce.data(),
                        serverKey.data(),
                        privateKey.data()) != 0)
    {
        throw std::runtime_error("DERP client authentication encryption failed.");
    }
    std::vector<std::uint8_t> payload;
    payload.reserve(publicKey.size() + nonce.size() + ciphertext.size());
    payload.insert(payload.end(), publicKey.begin(), publicKey.end());
    payload.insert(payload.end(), nonce.begin(), nonce.end());
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());
    return payload;
}

void DerpClient::Connect(const std::string& hostname)
{
    const std::string request = std::format("GET /derp HTTP/1.1\r\nHost: {}\r\n"
                                            "Connection: Upgrade\r\nUpgrade: DERP\r\n\r\n",
                                            hostname);
    Stream.WriteAll({request.begin(), request.end()});
    std::string response;
    while (response.find("\r\n\r\n") == std::string::npos)
    {
        std::vector<std::uint8_t> byte = Stream.ReadExact(1);
        response.push_back(static_cast<char>(byte.front()));
        if (response.size() > MaximumHttpHeaderSize)
        {
            throw std::runtime_error("DERP HTTP response headers are too large.");
        }
    }
    if (response.rfind("HTTP/1.1 101", 0) != 0)
    {
        throw std::runtime_error("DERP HTTP upgrade was rejected.");
    }

    Frame greeting = ReadFrame();
    if (greeting.Type != ServerKeyFrame || greeting.Payload.size() < ServerGreetingSize ||
        !std::equal(DerpMagic.begin(), DerpMagic.end(), greeting.Payload.begin()))
    {
        throw std::runtime_error("Invalid DERP server greeting.");
    }
    std::copy_n(greeting.Payload.begin() + 8, ServerKey.size(), ServerKey.begin());

    const std::vector<std::uint8_t> payload =
        Authenticate ? Authenticate(ServerKey) : BuildClientInfo(PrivateKey, PublicKey, ServerKey);
    if (payload.size() < Key{}.size() + crypto_box_NONCEBYTES + crypto_box_MACBYTES)
    {
        throw std::runtime_error("DERP authenticator returned an invalid ClientInfo envelope.");
    }
    WriteFrame(ClientInfoFrame, payload);

    Frame serverInfo = ReadFrame();
    if (serverInfo.Type != ServerInfoFrame ||
        serverInfo.Payload.size() < crypto_box_NONCEBYTES + crypto_box_MACBYTES)
    {
        throw std::runtime_error("DERP server did not authenticate the client.");
    }
    if (!Authenticate)
    {
        const std::size_t encryptedSize = serverInfo.Payload.size() - crypto_box_NONCEBYTES;
        std::vector<std::uint8_t> serverPlaintext(encryptedSize - crypto_box_MACBYTES);
        if (crypto_box_open_easy(serverPlaintext.data(),
                                 serverInfo.Payload.data() + crypto_box_NONCEBYTES,
                                 encryptedSize,
                                 serverInfo.Payload.data(),
                                 ServerKey.data(),
                                 PrivateKey.data()) != 0)
        {
            throw std::runtime_error("DERP server authentication failed.");
        }
    }
    Log(LogLevel::Info, "derp", "authenticated with " + hostname);
}

void DerpClient::Send(const Key& destination, const std::vector<std::uint8_t>& packet)
{
    std::vector<std::uint8_t> payload(destination.begin(), destination.end());
    payload.insert(payload.end(), packet.begin(), packet.end());
    WriteFrame(SendPacketFrame, payload);
}

DerpClient::Packet DerpClient::Receive()
{
    while (true)
    {
        Frame frame = ReadFrame();
        if (frame.Type == ReceivePacketFrame && frame.Payload.size() >= Key{}.size())
        {
            Packet packet;
            std::copy_n(frame.Payload.begin(), packet.Source.size(), packet.Source.begin());
            packet.Payload.assign(frame.Payload.begin() +
                                      static_cast<std::ptrdiff_t>(packet.Source.size()),
                                  frame.Payload.end());
            return packet;
        }
        if (frame.Type == PingFrame)
        {
            WriteFrame(PongFrame, frame.Payload);
        }
        else if (frame.Type != KeepAliveFrame)
        {
            continue;
        }
    }
}

std::optional<DerpClient::Packet> DerpClient::ReceiveAvailable()
{
    auto hasCompleteFrame = [&]()
    {
        if (ReceiveBuffer.size() < FrameHeaderSize)
        {
            return false;
        }
        const std::uint32_t size = (static_cast<std::uint32_t>(ReceiveBuffer[1]) << 24) |
                                   (static_cast<std::uint32_t>(ReceiveBuffer[2]) << 16) |
                                   (static_cast<std::uint32_t>(ReceiveBuffer[3]) << 8) |
                                   ReceiveBuffer[4];
        return ReceiveBuffer.size() >= FrameHeaderSize + size;
    };

    if (!hasCompleteFrame())
    {
        std::optional<std::vector<std::uint8_t>> available = Stream.TryReadSome(MaximumFrameSize);
        if (!available)
        {
            return std::nullopt;
        }
        std::vector<std::uint8_t> data = std::move(*available);
        if (data.empty())
        {
            throw std::runtime_error("DERP stream closed.");
        }
        ReceiveBuffer.insert(ReceiveBuffer.end(), data.begin(), data.end());
    }
    if (ReceiveBuffer.size() < FrameHeaderSize)
    {
        return std::nullopt;
    }
    const std::uint32_t size = (static_cast<std::uint32_t>(ReceiveBuffer[1]) << 24) |
                               (static_cast<std::uint32_t>(ReceiveBuffer[2]) << 16) |
                               (static_cast<std::uint32_t>(ReceiveBuffer[3]) << 8) |
                               ReceiveBuffer[4];
    if (size > MaximumFrameSize)
    {
        throw std::runtime_error("DERP frame exceeds the protocol limit.");
    }
    if (ReceiveBuffer.size() < FrameHeaderSize + size)
    {
        return std::nullopt;
    }

    Frame frame{ReceiveBuffer[0],
                {ReceiveBuffer.begin() + FrameHeaderSize,
                 ReceiveBuffer.begin() + static_cast<std::ptrdiff_t>(FrameHeaderSize + size)}};
    ReceiveBuffer.erase(ReceiveBuffer.begin(),
                        ReceiveBuffer.begin() +
                            static_cast<std::ptrdiff_t>(FrameHeaderSize + size));
    if (frame.Type == PingFrame)
    {
        WriteFrame(PongFrame, frame.Payload);
        return std::nullopt;
    }
    if (frame.Type != ReceivePacketFrame || frame.Payload.size() < Key{}.size())
    {
        return std::nullopt;
    }
    Packet packet;
    std::copy_n(frame.Payload.begin(), packet.Source.size(), packet.Source.begin());
    packet.Payload.assign(frame.Payload.begin() + static_cast<std::ptrdiff_t>(packet.Source.size()),
                          frame.Payload.end());
    return packet;
}

std::vector<DerpClient::Packet> DerpClient::ReceiveAvailableBatch()
{
    std::vector<Packet> packets;
    for (std::size_t iteration = 0; iteration < MaximumReceiveBatchFrames; ++iteration)
    {
        if (ReceiveBuffer.size() >= FrameHeaderSize)
        {
            const std::uint32_t size = (static_cast<std::uint32_t>(ReceiveBuffer[1]) << 24) |
                                       (static_cast<std::uint32_t>(ReceiveBuffer[2]) << 16) |
                                       (static_cast<std::uint32_t>(ReceiveBuffer[3]) << 8) |
                                       ReceiveBuffer[4];
            if (size > MaximumFrameSize)
            {
                throw std::runtime_error("DERP frame exceeds the protocol limit.");
            }
            if (ReceiveBuffer.size() >= FrameHeaderSize + size)
            {
                const std::uint8_t type = ReceiveBuffer[0];
                std::vector<std::uint8_t> payload(
                    ReceiveBuffer.begin() + FrameHeaderSize,
                    ReceiveBuffer.begin() + static_cast<std::ptrdiff_t>(FrameHeaderSize + size));
                ReceiveBuffer.erase(ReceiveBuffer.begin(),
                                    ReceiveBuffer.begin() +
                                        static_cast<std::ptrdiff_t>(FrameHeaderSize + size));
                if (type == PingFrame)
                {
                    WriteFrame(PongFrame, payload);
                }
                else if (type == PeerGoneFrame && payload.size() >= Key{}.size())
                {
                    Log(LogLevel::Debug,
                        "derp",
                        "peer unavailable key=" + BytesToHex(payload.data(), Key{}.size()));
                }
                else if (type == HealthFrame)
                {
                    Log(LogLevel::Warning,
                        "derp",
                        "server health: " + std::string(payload.begin(), payload.end()));
                }
                else if (type == ReceivePacketFrame && payload.size() >= Key{}.size())
                {
                    Packet packet;
                    std::copy_n(payload.begin(), packet.Source.size(), packet.Source.begin());
                    packet.Payload.assign(payload.begin() +
                                              static_cast<std::ptrdiff_t>(packet.Source.size()),
                                          payload.end());
                    packets.push_back(std::move(packet));
                }
                continue;
            }
        }

        std::optional<std::vector<std::uint8_t>> available =
            Stream.TryReadSome(MaximumFrameSize - ReceiveBuffer.size());
        if (!available)
        {
            break;
        }
        if (available->empty())
        {
            throw std::runtime_error("DERP stream closed.");
        }
        ReceiveBuffer.insert(ReceiveBuffer.end(), available->begin(), available->end());
    }
    return packets;
}

bool DerpClient::HasBufferedInput() const
{
    if (ReceiveBuffer.size() >= FrameHeaderSize)
    {
        const std::uint32_t size = (static_cast<std::uint32_t>(ReceiveBuffer[1]) << 24) |
                                   (static_cast<std::uint32_t>(ReceiveBuffer[2]) << 16) |
                                   (static_cast<std::uint32_t>(ReceiveBuffer[3]) << 8) |
                                   ReceiveBuffer[4];
        if (ReceiveBuffer.size() >= FrameHeaderSize + size)
        {
            return true;
        }
    }
    return Stream.HasBufferedInput();
}

void DerpClient::SetPreferred(bool preferred)
{
    WriteFrame(PreferredFrame, {static_cast<std::uint8_t>(preferred ? 1 : 0)});
}

void DerpClient::Flush()
{
    while (SendOffset < SendBuffer.size())
    {
        const std::optional<std::size_t> written =
            Stream.TryWriteSome(SendBuffer.data() + SendOffset, SendBuffer.size() - SendOffset);
        if (!written)
        {
            return;
        }
        if (*written == 0)
        {
            throw std::runtime_error("DERP stream closed during write.");
        }
        SendOffset += *written;
    }
    SendBuffer.clear();
    SendOffset = 0;
}

bool DerpClient::HasPendingOutput() const
{
    return SendOffset < SendBuffer.size();
}

void DerpClient::WriteFrame(std::uint8_t type, const std::vector<std::uint8_t>& payload)
{
    if (payload.size() > MaximumFrameSize)
    {
        throw std::runtime_error("DERP frame is too large.");
    }
    const std::uint32_t size = static_cast<std::uint32_t>(payload.size());
    std::vector<std::uint8_t> frame{type,
                                    static_cast<std::uint8_t>(size >> 24),
                                    static_cast<std::uint8_t>(size >> 16),
                                    static_cast<std::uint8_t>(size >> 8),
                                    static_cast<std::uint8_t>(size)};
    frame.insert(frame.end(), payload.begin(), payload.end());
    SendBuffer.insert(SendBuffer.end(), frame.begin(), frame.end());
    Flush();
}

DerpClient::Frame DerpClient::ReadFrame()
{
    std::vector<std::uint8_t> header = Stream.ReadExact(FrameHeaderSize);
    const std::uint32_t size = (static_cast<std::uint32_t>(header[1]) << 24) |
                               (static_cast<std::uint32_t>(header[2]) << 16) |
                               (static_cast<std::uint32_t>(header[3]) << 8) | header[4];
    if (size > MaximumFrameSize)
    {
        throw std::runtime_error("DERP frame exceeds the protocol limit.");
    }
    return Frame{.Type = header[0], .Payload = Stream.ReadExact(size)};
}

} // namespace tailgate::protocol
