#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace tailgate::uwp::app_service
{

// Every datagram uses one versioned envelope with a message type, request sequence, explicit
// header size, and payload size. Message payloads are typed length-value fields: decoders require
// known fields but ignore unknown ones, so a newer sender can extend an existing message without
// defining another endpoint or magic packet format.
enum class MessageType : std::uint8_t
{
    PingRequest = 1,
    PingResponse = 2,
    ExitNodeRequest = 3,
    ExitNodeResponse = 4,
};

enum class Status : std::uint8_t
{
    Ok = 0,
    NoMatchingPeer = 1,
    NoDiscoKey = 2,
    NoMatchingExitNode = 3,
};

struct Field
{
    std::uint8_t Type = 0;
    std::vector<std::uint8_t> Value;
};

struct Message
{
    MessageType Type = MessageType::PingRequest;
    std::uint64_t Sequence = 0;
    std::vector<Field> Fields;
};

struct PingRequest
{
    std::uint64_t Sequence = 0;
    std::string Target;
};

struct PingResponse
{
    Status Result = Status::Ok;
    std::uint64_t Sequence = 0;
    std::uint32_t LatencyMicroseconds = 0;
    bool Direct = false;
    std::string Relay;
    std::string Endpoint;
};

struct ExitNodeRequest
{
    std::uint64_t Sequence = 0;
    std::string ExitNode;
    bool PreserveSelection = false;
};

struct ExitNodeResponse
{
    Status Result = Status::Ok;
    std::uint64_t Sequence = 0;
    std::string ExitNode;
};

[[nodiscard]] bool IsMessage(std::span<const std::uint8_t> payload);
[[nodiscard]] std::optional<Message> DecodeMessage(std::span<const std::uint8_t> payload);

[[nodiscard]] std::vector<std::uint8_t> EncodePingRequest(const PingRequest& request);
[[nodiscard]] std::optional<PingRequest> DecodePingRequest(const Message& message);
[[nodiscard]] std::vector<std::uint8_t> EncodePingResponse(const PingResponse& response);
[[nodiscard]] std::optional<PingResponse> DecodePingResponse(const Message& message);

[[nodiscard]] std::vector<std::uint8_t> EncodeExitNodeRequest(const ExitNodeRequest& request);
[[nodiscard]] std::optional<ExitNodeRequest> DecodeExitNodeRequest(const Message& message);
[[nodiscard]] std::vector<std::uint8_t> EncodeExitNodeResponse(const ExitNodeResponse& response);
[[nodiscard]] std::optional<ExitNodeResponse> DecodeExitNodeResponse(const Message& message);

} // namespace tailgate::uwp::app_service
