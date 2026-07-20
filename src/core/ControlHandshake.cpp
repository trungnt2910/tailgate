#include "tailgate/protocol/ControlHandshake.h"

#include "tailgate/protocol/Base64.h"

#include <algorithm>
#include <array>
#include <format>
#include <stdexcept>

namespace tailgate::protocol
{
namespace
{

constexpr std::size_t ReadChunkSize = 2048;
constexpr std::size_t NoiseFrameHeaderSize = 3;
constexpr std::uint8_t NoiseMessageTwoType = 0x02;
constexpr std::size_t MaximumDiagnosticHeaderLength = 200;

} // namespace

ControlHandshake::ControlHandshake(Bytes32 machinePrivateKey, Bytes32 ephemeralPrivateKey)
    : m_noise(machinePrivateKey, ephemeralPrivateKey)
{
}

std::vector<std::uint8_t>
ControlHandshake::BuildUpgradeRequest(const std::string& host,
                                      const std::vector<std::uint8_t>& message1)
{
    const std::string encoded = Base64Encode(message1);
    const std::string request = std::format("POST /ts2021 HTTP/1.1\r\nHost: {}\r\n"
                                            "Upgrade: tailscale-control-protocol\r\n"
                                            "Connection: Upgrade\r\n"
                                            "User-Agent: Tailgate\r\n"
                                            "X-Tailscale-Handshake: {}\r\n"
                                            "Content-Length: 0\r\n\r\n",
                                            host,
                                            encoded);
    return std::vector<std::uint8_t>(request.begin(), request.end());
}

std::size_t ControlHandshake::FindHeaderEnd(const std::vector<std::uint8_t>& data)
{
    const std::array<std::uint8_t, 4> delimiter{'\r', '\n', '\r', '\n'};
    auto match = std::search(data.begin(), data.end(), delimiter.begin(), delimiter.end());
    if (match == data.end())
    {
        return std::string::npos;
    }
    return static_cast<std::size_t>(std::distance(data.begin(), match)) + delimiter.size();
}

ControlHandshakeResult ControlHandshake::Run(IByteStream& stream, const std::string& host)
{
    std::vector<std::uint8_t> message1 = m_noise.WriteMessage1();
    stream.WriteAll(BuildUpgradeRequest(host, message1));

    std::vector<std::uint8_t> response;
    std::size_t headerEnd = std::string::npos;
    while (headerEnd == std::string::npos)
    {
        std::vector<std::uint8_t> chunk = stream.ReadSome(ReadChunkSize);
        if (chunk.empty())
        {
            throw std::runtime_error("Control server closed during HTTP upgrade.");
        }
        response.insert(response.end(), chunk.begin(), chunk.end());
        headerEnd = FindHeaderEnd(response);
    }

    std::string headers(response.begin(),
                        response.begin() + static_cast<std::ptrdiff_t>(headerEnd));
    if (headers.find("101") == std::string::npos)
    {
        throw std::runtime_error(std::format("Control server did not switch protocols: {}.",
                                             headers.substr(0, MaximumDiagnosticHeaderLength)));
    }

    std::vector<std::uint8_t> body(response.begin() + static_cast<std::ptrdiff_t>(headerEnd),
                                   response.end());
    while (body.size() < NoiseFrameHeaderSize)
    {
        std::vector<std::uint8_t> chunk = stream.ReadSome(NoiseFrameHeaderSize - body.size());
        body.insert(body.end(), chunk.begin(), chunk.end());
    }

    if (body[0] != NoiseMessageTwoType)
    {
        throw std::runtime_error("Unexpected Noise message type from control server.");
    }
    std::size_t payloadLength = (static_cast<std::size_t>(body[1]) << 8) | body[2];
    while (body.size() < NoiseFrameHeaderSize + payloadLength)
    {
        std::vector<std::uint8_t> chunk =
            stream.ReadSome(NoiseFrameHeaderSize + payloadLength - body.size());
        body.insert(body.end(), chunk.begin(), chunk.end());
    }

    std::vector<std::uint8_t> message2(
        body.begin() + NoiseFrameHeaderSize,
        body.begin() + static_cast<std::ptrdiff_t>(NoiseFrameHeaderSize + payloadLength));
    std::vector<std::uint8_t> extra(
        body.begin() + static_cast<std::ptrdiff_t>(NoiseFrameHeaderSize + payloadLength),
        body.end());
    NoiseKeys keys = m_noise.ReadMessage2(message2);
    return ControlHandshakeResult{.Keys = keys, .ProactiveFrames = extra};
}

} // namespace tailgate::protocol
