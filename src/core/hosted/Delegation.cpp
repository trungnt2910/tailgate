#include "tailgate/hosted/Delegation.h"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace tailgate::hosted
{
namespace
{

constexpr std::size_t IdentitySize = 3 * sizeof(std::uint64_t);
constexpr std::size_t RequestHeaderSize = IdentitySize + 2;
constexpr std::size_t ReplySize = IdentitySize + 2;
constexpr std::size_t MaximumRegions = std::numeric_limits<std::uint8_t>::max();
constexpr unsigned ByteBits = 8;

void Append64(std::vector<std::uint8_t>& bytes, std::uint64_t value)
{
    for (std::size_t index = sizeof(value); index != 0; --index)
    {
        bytes.push_back(static_cast<std::uint8_t>(value >> ((index - 1) * ByteBits)));
    }
}

std::uint64_t Read64(const std::vector<std::uint8_t>& bytes, std::size_t offset)
{
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < sizeof(value); ++index)
    {
        value = (value << ByteBits) | bytes[offset + index];
    }
    return value;
}

std::vector<std::uint8_t>
Identity(std::uint64_t generation, std::uint64_t request, std::uint64_t revision)
{
    if (generation == 0 || request == 0 || revision == 0)
    {
        throw std::invalid_argument("delegation identity must be nonzero");
    }
    std::vector<std::uint8_t> bytes;
    Append64(bytes, generation);
    Append64(bytes, request);
    Append64(bytes, revision);
    return bytes;
}

} // namespace

Frame EncodeMapAcknowledgement(std::uint64_t revision)
{
    if (revision == 0)
    {
        throw std::invalid_argument("map revision must be nonzero");
    }
    std::vector<std::uint8_t> bytes;
    Append64(bytes, revision);
    return {MessageType::NetworkMapAck, std::move(bytes)};
}

std::optional<std::uint64_t> DecodeMapAcknowledgement(const Frame& frame)
{
    if (frame.Type() != MessageType::NetworkMapAck ||
        frame.Payload().size() != sizeof(std::uint64_t))
    {
        return {};
    }
    const auto revision = Read64(frame.Payload(), 0);
    return revision == 0 ? std::nullopt : std::optional(revision);
}

Frame EncodeDelegation(const DelegationRequest& request)
{
    if (request.Regions.empty() || request.Regions.size() > MaximumRegions ||
        !std::ranges::is_sorted(request.Regions) ||
        std::ranges::adjacent_find(request.Regions) != request.Regions.end() ||
        request.Regions.front() == 0 || request.Action > DelegationAction::Commit)
    {
        throw std::invalid_argument("invalid delegation request");
    }
    auto bytes = Identity(request.Generation, request.RequestId, request.MapRevision);
    bytes.push_back(static_cast<std::uint8_t>(request.Action));
    bytes.push_back(static_cast<std::uint8_t>(request.Regions.size()));
    for (auto region : request.Regions)
    {
        bytes.push_back(static_cast<std::uint8_t>(region >> ByteBits));
        bytes.push_back(static_cast<std::uint8_t>(region));
    }
    return {MessageType::Delegation, std::move(bytes)};
}

Frame EncodeDelegation(const DelegationReply& reply)
{
    if (reply.Status > DelegationStatus::Failed ||
        reply.Failure > DelegationFailure::LeaseExpired ||
        ((reply.Status == DelegationStatus::Failed) != (reply.Failure != DelegationFailure::None)))
    {
        throw std::invalid_argument("invalid delegation reply");
    }
    auto bytes = Identity(reply.Generation, reply.RequestId, reply.MapRevision);
    bytes.push_back(static_cast<std::uint8_t>(reply.Status));
    bytes.push_back(static_cast<std::uint8_t>(reply.Failure));
    return {MessageType::DelegationReply, std::move(bytes)};
}

std::optional<DelegationRequest> DecodeDelegationRequest(const Frame& frame)
{
    const auto& bytes = frame.Payload();
    if (frame.Type() != MessageType::Delegation || bytes.size() < RequestHeaderSize ||
        bytes[IdentitySize] > static_cast<std::uint8_t>(DelegationAction::Commit))
    {
        return {};
    }
    const auto count = bytes[IdentitySize + 1];
    if (count == 0 || count > MaximumRegions ||
        bytes.size() != RequestHeaderSize + count * sizeof(std::uint16_t))
    {
        return {};
    }
    DelegationRequest request{.Generation = Read64(bytes, 0),
                              .RequestId = Read64(bytes, sizeof(std::uint64_t)),
                              .MapRevision = Read64(bytes, 2 * sizeof(std::uint64_t)),
                              .Action = static_cast<DelegationAction>(bytes[IdentitySize]),
                              .Regions = {}};
    if (request.Generation == 0 || request.RequestId == 0 || request.MapRevision == 0)
    {
        return {};
    }
    for (std::size_t index = 0; index < count; ++index)
    {
        const auto offset = RequestHeaderSize + index * sizeof(std::uint16_t);
        const auto region =
            static_cast<std::uint16_t>((bytes[offset] << ByteBits) | bytes[offset + 1]);
        if (region == 0 || (!request.Regions.empty() && region <= request.Regions.back()))
        {
            return {};
        }
        request.Regions.push_back(region);
    }
    return request;
}

std::optional<DelegationReply> DecodeDelegationReply(const Frame& frame)
{
    const auto& bytes = frame.Payload();
    if (frame.Type() != MessageType::DelegationReply || bytes.size() != ReplySize ||
        bytes[IdentitySize] > static_cast<std::uint8_t>(DelegationStatus::Failed) ||
        bytes[IdentitySize + 1] > static_cast<std::uint8_t>(DelegationFailure::LeaseExpired))
    {
        return {};
    }
    DelegationReply reply{.Generation = Read64(bytes, 0),
                          .RequestId = Read64(bytes, sizeof(std::uint64_t)),
                          .MapRevision = Read64(bytes, 2 * sizeof(std::uint64_t)),
                          .Status = static_cast<DelegationStatus>(bytes[IdentitySize]),
                          .Failure = static_cast<DelegationFailure>(bytes[IdentitySize + 1])};
    if (reply.Generation == 0 || reply.RequestId == 0 || reply.MapRevision == 0 ||
        ((reply.Status == DelegationStatus::Failed) != (reply.Failure != DelegationFailure::None)))
    {
        return {};
    }
    return reply;
}

} // namespace tailgate::hosted
