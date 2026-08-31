#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace tailgate::control::base
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

using H2Headers = std::unordered_multimap<std::string, std::string>;

class H2HeaderDecoder final
{
public:
    [[nodiscard]] std::optional<H2Headers> Decode(const std::vector<std::uint8_t>& headerBlock);

private:
    static constexpr std::size_t DefaultDynamicTableSize = 4096;

    std::deque<std::pair<std::string, std::string>> m_dynamicTable;
    std::size_t m_dynamicTableSize = 0;
    std::size_t m_maximumDynamicTableSize = DefaultDynamicTableSize;
};

class H2Codec final
{
public:
    [[nodiscard]] static std::vector<std::uint8_t> BuildPreface(std::uint32_t initialWindowSize);
    [[nodiscard]] static std::vector<std::uint8_t> BuildSettingsAck();
    [[nodiscard]] static std::vector<std::uint8_t>
    BuildPingAck(const std::vector<std::uint8_t>& payload);
    [[nodiscard]] static std::vector<std::uint8_t> BuildWindowUpdate(std::uint32_t streamId,
                                                                     std::uint32_t increment);
    [[nodiscard]] static std::vector<std::uint8_t>
    BuildHeaders(const std::string& method,
                 const std::string& path,
                 const std::string& authority,
                 const std::string& contentType,
                 const std::vector<std::pair<std::string, std::string>>& extraHeaders,
                 std::uint32_t streamId,
                 bool endStream);
    [[nodiscard]] static std::vector<std::uint8_t>
    BuildData(const std::vector<std::uint8_t>& data, std::uint32_t streamId, bool endStream);
    [[nodiscard]] static std::optional<H2Headers>
    DecodeHeaders(const std::vector<std::uint8_t>& headerBlock);
    [[nodiscard]] static std::optional<int> Status(const H2Headers& headers);
    [[nodiscard]] static std::optional<int>
    DecodeStatus(const std::vector<std::uint8_t>& headerBlock);
    [[nodiscard]] static std::vector<H2Frame> ParseFrames(const std::vector<std::uint8_t>& data);
    [[nodiscard]] static std::vector<H2Frame> TakeCompleteFrames(std::vector<std::uint8_t>& buffer);
};

} // namespace tailgate::control::base
