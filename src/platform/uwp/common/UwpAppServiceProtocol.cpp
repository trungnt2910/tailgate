#include "UwpAppServiceProtocol.h"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace tailgate::uwp::app_service
{
namespace
{

constexpr std::array<std::uint8_t, 5> Magic{'T', 'G', 'A', 'P', 'P'};
constexpr std::uint8_t Version = 1;
constexpr std::size_t VersionOffset = 5;
constexpr std::size_t HeaderSizeOffset = 6;
constexpr std::size_t TypeOffset = 7;
constexpr std::size_t FlagsOffset = 8;
constexpr std::size_t ReservedOffset = 9;
constexpr std::size_t SequenceOffset = 10;
constexpr std::size_t PayloadLengthOffset = 18;
constexpr std::size_t FixedHeaderSize = 20;
constexpr std::size_t FieldHeaderSize = 3;
constexpr std::size_t MaximumFieldSize = std::numeric_limits<std::uint16_t>::max();
constexpr char MessageTooLargeError[] = "UWP app-service message is too large";
constexpr char FieldTooLargeError[] = "UWP app-service field is too large";

enum class FieldType : std::uint8_t
{
    Status = 1,
    Target = 2,
    LatencyMicroseconds = 3,
    Direct = 4,
    Relay = 5,
    Endpoint = 6,
    ExitNode = 7,
    PreserveSelection = 8,
};

void AppendUint16(std::vector<std::uint8_t>& output, std::uint16_t value)
{
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void AppendUint64(std::vector<std::uint8_t>& output, std::uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8)
    {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

std::uint16_t ReadUint16(std::span<const std::uint8_t> input, std::size_t offset)
{
    return static_cast<std::uint16_t>((input[offset] << 8U) | input[offset + 1]);
}

std::uint32_t ReadUint32(std::span<const std::uint8_t> input)
{
    std::uint32_t result = 0;
    for (std::uint8_t byte : input)
    {
        result = (result << 8U) | byte;
    }
    return result;
}

std::uint64_t ReadUint64(std::span<const std::uint8_t> input, std::size_t offset)
{
    std::uint64_t result = 0;
    for (std::size_t index = 0; index < sizeof(result); ++index)
    {
        result = (result << 8U) | input[offset + index];
    }
    return result;
}

void AppendField(std::vector<std::uint8_t>& payload,
                 FieldType type,
                 std::span<const std::uint8_t> value)
{
    if (value.size() > MaximumFieldSize)
    {
        throw std::invalid_argument(FieldTooLargeError);
    }
    payload.push_back(static_cast<std::uint8_t>(type));
    AppendUint16(payload, static_cast<std::uint16_t>(value.size()));
    payload.insert(payload.end(), value.begin(), value.end());
}

void AppendByteField(std::vector<std::uint8_t>& payload, FieldType type, std::uint8_t value)
{
    AppendField(payload, type, std::span(&value, 1));
}

void AppendUint32Field(std::vector<std::uint8_t>& payload, FieldType type, std::uint32_t value)
{
    std::array<std::uint8_t, 4> encoded{};
    for (int shift = 24, index = 0; shift >= 0; shift -= 8, ++index)
    {
        encoded[static_cast<std::size_t>(index)] = static_cast<std::uint8_t>(value >> shift);
    }
    AppendField(payload, type, encoded);
}

void AppendStringField(std::vector<std::uint8_t>& payload, FieldType type, const std::string& value)
{
    AppendField(payload,
                type,
                std::span(reinterpret_cast<const std::uint8_t*>(value.data()), value.size()));
}

std::vector<std::uint8_t>
EncodeMessage(MessageType type, std::uint64_t sequence, std::vector<std::uint8_t> payload)
{
    if (payload.size() > MaximumFieldSize)
    {
        throw std::invalid_argument(MessageTooLargeError);
    }
    std::vector<std::uint8_t> result;
    result.reserve(FixedHeaderSize + payload.size());
    result.insert(result.end(), Magic.begin(), Magic.end());
    result.push_back(Version);
    result.push_back(static_cast<std::uint8_t>(FixedHeaderSize));
    result.push_back(static_cast<std::uint8_t>(type));
    result.push_back(0);
    result.push_back(0);
    AppendUint64(result, sequence);
    AppendUint16(result, static_cast<std::uint16_t>(payload.size()));
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::optional<std::span<const std::uint8_t>>
FindField(const Message& message, FieldType type, std::optional<std::size_t> size = std::nullopt)
{
    std::optional<std::span<const std::uint8_t>> result;
    for (const Field& field : message.Fields)
    {
        if (field.Type != static_cast<std::uint8_t>(type))
        {
            continue;
        }
        if (result || (size && field.Value.size() != *size))
        {
            return std::nullopt;
        }
        result = field.Value;
    }
    return result;
}

std::optional<std::string> FindStringField(const Message& message, FieldType type)
{
    const std::optional<std::span<const std::uint8_t>> field = FindField(message, type);
    if (!field)
    {
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char*>(field->data()), field->size());
}

std::optional<Status> FindStatus(const Message& message)
{
    const std::optional<std::span<const std::uint8_t>> field =
        FindField(message, FieldType::Status, 1);
    if (!field || (*field)[0] > static_cast<std::uint8_t>(Status::NoMatchingExitNode))
    {
        return std::nullopt;
    }
    return static_cast<Status>((*field)[0]);
}

std::optional<bool> FindBooleanField(const Message& message, FieldType type)
{
    const std::optional<std::span<const std::uint8_t>> field = FindField(message, type, 1);
    if (!field || (*field)[0] > 1)
    {
        return std::nullopt;
    }
    return (*field)[0] != 0;
}

} // namespace

bool IsMessage(std::span<const std::uint8_t> payload)
{
    return payload.size() >= Magic.size() &&
           std::equal(Magic.begin(), Magic.end(), payload.begin());
}

std::optional<Message> DecodeMessage(std::span<const std::uint8_t> payload)
{
    if (payload.size() < FixedHeaderSize || !IsMessage(payload) ||
        payload[VersionOffset] != Version || payload[HeaderSizeOffset] < FixedHeaderSize)
    {
        return std::nullopt;
    }
    const std::size_t headerSize = payload[HeaderSizeOffset];
    const std::size_t payloadSize = ReadUint16(payload, PayloadLengthOffset);
    if (payload.size() != headerSize + payloadSize)
    {
        return std::nullopt;
    }
    Message result;
    result.Type = static_cast<MessageType>(payload[TypeOffset]);
    result.Sequence = ReadUint64(payload, SequenceOffset);
    std::size_t offset = headerSize;
    while (offset < payload.size())
    {
        if (payload.size() - offset < FieldHeaderSize)
        {
            return std::nullopt;
        }
        const std::uint8_t type = payload[offset];
        const std::size_t fieldSize = ReadUint16(payload, offset + 1);
        offset += FieldHeaderSize;
        if (fieldSize > payload.size() - offset)
        {
            return std::nullopt;
        }
        result.Fields.push_back(Field{
            .Type = type,
            .Value = std::vector<std::uint8_t>(
                payload.begin() + static_cast<std::ptrdiff_t>(offset),
                payload.begin() + static_cast<std::ptrdiff_t>(offset + fieldSize)),
        });
        offset += fieldSize;
    }
    (void)payload[FlagsOffset];
    (void)payload[ReservedOffset];
    return result;
}

std::vector<std::uint8_t> EncodePingRequest(const PingRequest& request)
{
    std::vector<std::uint8_t> payload;
    AppendStringField(payload, FieldType::Target, request.Target);
    return EncodeMessage(MessageType::PingRequest, request.Sequence, std::move(payload));
}

std::optional<PingRequest> DecodePingRequest(const Message& message)
{
    const std::optional<std::string> target = FindStringField(message, FieldType::Target);
    if (message.Type != MessageType::PingRequest || !target || target->empty())
    {
        return std::nullopt;
    }
    return PingRequest{.Sequence = message.Sequence, .Target = *target};
}

std::vector<std::uint8_t> EncodePingResponse(const PingResponse& response)
{
    std::vector<std::uint8_t> payload;
    AppendByteField(payload, FieldType::Status, static_cast<std::uint8_t>(response.Result));
    AppendUint32Field(payload, FieldType::LatencyMicroseconds, response.LatencyMicroseconds);
    AppendByteField(payload, FieldType::Direct, response.Direct ? 1 : 0);
    AppendStringField(payload, FieldType::Relay, response.Relay);
    AppendStringField(payload, FieldType::Endpoint, response.Endpoint);
    return EncodeMessage(MessageType::PingResponse, response.Sequence, std::move(payload));
}

std::optional<PingResponse> DecodePingResponse(const Message& message)
{
    const std::optional<Status> status = FindStatus(message);
    const std::optional<std::span<const std::uint8_t>> latency =
        FindField(message, FieldType::LatencyMicroseconds, 4);
    const std::optional<bool> direct = FindBooleanField(message, FieldType::Direct);
    const std::optional<std::string> relay = FindStringField(message, FieldType::Relay);
    const std::optional<std::string> endpoint = FindStringField(message, FieldType::Endpoint);
    if (message.Type != MessageType::PingResponse || !status || !latency || !direct || !relay ||
        !endpoint)
    {
        return std::nullopt;
    }
    return PingResponse{
        .Result = *status,
        .Sequence = message.Sequence,
        .LatencyMicroseconds = ReadUint32(*latency),
        .Direct = *direct,
        .Relay = *relay,
        .Endpoint = *endpoint,
    };
}

std::vector<std::uint8_t> EncodeExitNodeRequest(const ExitNodeRequest& request)
{
    std::vector<std::uint8_t> payload;
    AppendStringField(payload, FieldType::ExitNode, request.ExitNode);
    AppendByteField(payload, FieldType::PreserveSelection, request.PreserveSelection ? 1 : 0);
    return EncodeMessage(MessageType::ExitNodeRequest, request.Sequence, std::move(payload));
}

std::optional<ExitNodeRequest> DecodeExitNodeRequest(const Message& message)
{
    const std::optional<std::string> exitNode = FindStringField(message, FieldType::ExitNode);
    const std::optional<bool> preserve = FindBooleanField(message, FieldType::PreserveSelection);
    if (message.Type != MessageType::ExitNodeRequest || !exitNode || !preserve)
    {
        return std::nullopt;
    }
    return ExitNodeRequest{
        .Sequence = message.Sequence,
        .ExitNode = *exitNode,
        .PreserveSelection = *preserve,
    };
}

std::vector<std::uint8_t> EncodeExitNodeResponse(const ExitNodeResponse& response)
{
    std::vector<std::uint8_t> payload;
    AppendByteField(payload, FieldType::Status, static_cast<std::uint8_t>(response.Result));
    AppendStringField(payload, FieldType::ExitNode, response.ExitNode);
    return EncodeMessage(MessageType::ExitNodeResponse, response.Sequence, std::move(payload));
}

std::optional<ExitNodeResponse> DecodeExitNodeResponse(const Message& message)
{
    const std::optional<Status> status = FindStatus(message);
    const std::optional<std::string> exitNode = FindStringField(message, FieldType::ExitNode);
    if (message.Type != MessageType::ExitNodeResponse || !status || !exitNode)
    {
        return std::nullopt;
    }
    return ExitNodeResponse{
        .Result = *status,
        .Sequence = message.Sequence,
        .ExitNode = *exitNode,
    };
}

} // namespace tailgate::uwp::app_service
