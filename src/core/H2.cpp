#include "tailgate/protocol/H2.h"

#include <algorithm>
#include <stdexcept>

namespace tailgate::protocol
{
namespace
{

constexpr std::uint8_t H2FlagEndStream = 0x01;
constexpr std::uint8_t H2FlagEndHeaders = 0x04;
constexpr std::uint8_t H2FlagAck = 0x01;
constexpr std::uint16_t H2SettingsInitialWindowSize = 0x04;

void AppendFrameHeader(std::vector<std::uint8_t>& out,
                       std::uint32_t length,
                       H2FrameType type,
                       std::uint8_t flags,
                       std::uint32_t streamId)
{
    out.push_back(static_cast<std::uint8_t>((length >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((length >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(length & 0xff));
    out.push_back(static_cast<std::uint8_t>(type));
    out.push_back(flags);
    out.push_back(static_cast<std::uint8_t>((streamId >> 24) & 0x7f));
    out.push_back(static_cast<std::uint8_t>((streamId >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((streamId >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(streamId & 0xff));
}

void AppendHpackIndexed(std::vector<std::uint8_t>& out, int index)
{
    if (index > 127)
    {
        throw std::runtime_error("HPACK indexed helper only supports small static indices");
    }
    out.push_back(static_cast<std::uint8_t>(0x80 | index));
}

void AppendHpackLiteralIndexed(std::vector<std::uint8_t>& out,
                               int nameIndex,
                               const std::string& value)
{
    if (nameIndex > 63 || value.size() > 127)
    {
        throw std::runtime_error("HPACK literal helper only supports small fields");
    }
    out.push_back(static_cast<std::uint8_t>(0x40 | nameIndex));
    out.push_back(static_cast<std::uint8_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

void AppendHpackLiteralNew(std::vector<std::uint8_t>& out,
                           const std::string& name,
                           const std::string& value)
{
    if (name.size() > 127 || value.size() > 127)
    {
        throw std::runtime_error("HPACK literal helper only supports small fields");
    }
    out.push_back(0x00);
    out.push_back(static_cast<std::uint8_t>(name.size()));
    out.insert(out.end(), name.begin(), name.end());
    out.push_back(static_cast<std::uint8_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

} // namespace

std::vector<std::uint8_t> BuildH2Preface(std::uint32_t initialWindowSize)
{
    const std::string preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    std::vector<std::uint8_t> out(preface.begin(), preface.end());
    AppendFrameHeader(out, 6, H2FrameType::Settings, 0, 0);
    out.push_back(static_cast<std::uint8_t>((H2SettingsInitialWindowSize >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(H2SettingsInitialWindowSize & 0xff));
    out.push_back(static_cast<std::uint8_t>((initialWindowSize >> 24) & 0xff));
    out.push_back(static_cast<std::uint8_t>((initialWindowSize >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((initialWindowSize >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(initialWindowSize & 0xff));
    return out;
}

std::vector<std::uint8_t> BuildH2SettingsAck()
{
    std::vector<std::uint8_t> out;
    AppendFrameHeader(out, 0, H2FrameType::Settings, H2FlagAck, 0);
    return out;
}

std::vector<std::uint8_t> BuildH2PingAck(const std::vector<std::uint8_t>& payload)
{
    constexpr std::size_t pingPayloadSize = 8;
    if (payload.size() != pingPayloadSize)
    {
        throw std::runtime_error("HTTP/2 PING payload must be 8 bytes");
    }
    std::vector<std::uint8_t> out;
    AppendFrameHeader(out, pingPayloadSize, H2FrameType::Ping, H2FlagAck, 0);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<std::uint8_t> BuildH2WindowUpdate(std::uint32_t streamId, std::uint32_t increment)
{
    std::vector<std::uint8_t> out;
    AppendFrameHeader(out, 4, H2FrameType::WindowUpdate, 0, streamId);
    out.push_back(static_cast<std::uint8_t>((increment >> 24) & 0x7f));
    out.push_back(static_cast<std::uint8_t>((increment >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((increment >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(increment & 0xff));
    return out;
}

std::vector<std::uint8_t>
BuildH2Headers(const std::string& method,
               const std::string& path,
               const std::string& authority,
               const std::string& contentType,
               const std::vector<std::pair<std::string, std::string>>& extraHeaders,
               std::uint32_t streamId,
               bool endStream)
{
    std::vector<std::uint8_t> hpack;
    if (method == "POST")
    {
        AppendHpackIndexed(hpack, 3);
    }
    else if (method == "GET")
    {
        AppendHpackIndexed(hpack, 2);
    }
    else
    {
        AppendHpackLiteralIndexed(hpack, 2, method);
    }

    if (path == "/")
    {
        AppendHpackIndexed(hpack, 4);
    }
    else
    {
        AppendHpackLiteralIndexed(hpack, 4, path);
    }

    AppendHpackIndexed(hpack, 6);
    AppendHpackLiteralIndexed(hpack, 1, authority);
    AppendHpackLiteralIndexed(hpack, 31, contentType);
    for (const auto& header : extraHeaders)
    {
        AppendHpackLiteralNew(hpack, header.first, header.second);
    }

    std::vector<std::uint8_t> out;
    std::uint8_t flags = H2FlagEndHeaders;
    if (endStream)
    {
        flags |= H2FlagEndStream;
    }
    AppendFrameHeader(
        out, static_cast<std::uint32_t>(hpack.size()), H2FrameType::Headers, flags, streamId);
    out.insert(out.end(), hpack.begin(), hpack.end());
    return out;
}

std::vector<std::uint8_t>
BuildH2Data(const std::vector<std::uint8_t>& data, std::uint32_t streamId, bool endStream)
{
    std::vector<std::uint8_t> out;
    AppendFrameHeader(out,
                      static_cast<std::uint32_t>(data.size()),
                      H2FrameType::Data,
                      endStream ? H2FlagEndStream : 0,
                      streamId);
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

std::vector<H2Frame> ParseH2Frames(const std::vector<std::uint8_t>& data)
{
    std::vector<std::uint8_t> copy = data;
    return TakeCompleteH2Frames(copy);
}

std::vector<H2Frame> TakeCompleteH2Frames(std::vector<std::uint8_t>& buffer)
{
    std::vector<H2Frame> frames;
    std::size_t offset = 0;
    while (offset + 9 <= buffer.size())
    {
        std::uint32_t length = (static_cast<std::uint32_t>(buffer[offset]) << 16) |
                               (static_cast<std::uint32_t>(buffer[offset + 1]) << 8) |
                               buffer[offset + 2];
        if (offset + 9 + length > buffer.size())
        {
            break;
        }

        H2Frame frame;
        frame.Length = length;
        frame.Type = static_cast<H2FrameType>(buffer[offset + 3]);
        frame.Flags = buffer[offset + 4];
        frame.StreamId = (static_cast<std::uint32_t>(buffer[offset + 5] & 0x7f) << 24) |
                         (static_cast<std::uint32_t>(buffer[offset + 6]) << 16) |
                         (static_cast<std::uint32_t>(buffer[offset + 7]) << 8) | buffer[offset + 8];
        frame.Payload.insert(frame.Payload.end(),
                             buffer.begin() + static_cast<std::ptrdiff_t>(offset + 9),
                             buffer.begin() + static_cast<std::ptrdiff_t>(offset + 9 + length));
        frames.push_back(std::move(frame));
        offset += 9 + length;
    }
    buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(offset));
    return frames;
}

} // namespace tailgate::protocol
