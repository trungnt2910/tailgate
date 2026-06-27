#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tailgate::protocol
{

enum class H2FrameType : std::uint8_t
{
    Data = 0x00,
    Headers = 0x01,
    Settings = 0x04,
    Ping = 0x06,
    GoAway = 0x07,
    WindowUpdate = 0x08,
};

struct H2Frame
{
    std::uint32_t Length = 0;
    H2FrameType Type = H2FrameType::Data;
    std::uint8_t Flags = 0;
    std::uint32_t StreamId = 0;
    std::vector<std::uint8_t> Payload;
};

[[nodiscard]] std::vector<std::uint8_t> BuildH2Preface(std::uint32_t initialWindowSize);
[[nodiscard]] std::vector<std::uint8_t> BuildH2SettingsAck();
[[nodiscard]] std::vector<std::uint8_t> BuildH2PingAck(const std::vector<std::uint8_t>& payload);
[[nodiscard]] std::vector<std::uint8_t> BuildH2WindowUpdate(std::uint32_t streamId,
                                                            std::uint32_t increment);
[[nodiscard]] std::vector<std::uint8_t>
BuildH2Headers(const std::string& method,
               const std::string& path,
               const std::string& authority,
               const std::string& contentType,
               const std::vector<std::pair<std::string, std::string>>& extraHeaders,
               std::uint32_t streamId,
               bool endStream);
[[nodiscard]] std::vector<std::uint8_t>
BuildH2Data(const std::vector<std::uint8_t>& data, std::uint32_t streamId, bool endStream);
[[nodiscard]] std::vector<H2Frame> ParseH2Frames(const std::vector<std::uint8_t>& data);
[[nodiscard]] std::vector<H2Frame> TakeCompleteH2Frames(std::vector<std::uint8_t>& buffer);

} // namespace tailgate::protocol
