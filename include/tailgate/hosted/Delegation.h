#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/hosted/Protocol.h>

namespace tailgate::hosted
{

enum class DelegationAction : std::uint8_t
{
    Prepare,
    Release,
    Acquire,
    Commit,
};

enum class DelegationStatus : std::uint8_t
{
    Prepared,
    Released,
    Ready,
    Committed,
    Failed,
};

enum class DelegationFailure : std::uint8_t
{
    None,
    StaleGeneration,
    StaleMap,
    InvalidState,
    UnknownRegion,
    LeaseExpired,
};

struct DelegationRequest
{
    std::uint64_t Generation = 0;
    std::uint64_t RequestId = 0;
    std::uint64_t MapRevision = 0;
    DelegationAction Action = DelegationAction::Prepare;
    std::vector<std::uint16_t> Regions;
    [[nodiscard]] bool operator==(const DelegationRequest&) const = default;
};

struct DelegationReply
{
    std::uint64_t Generation = 0;
    std::uint64_t RequestId = 0;
    std::uint64_t MapRevision = 0;
    DelegationStatus Status = DelegationStatus::Failed;
    DelegationFailure Failure = DelegationFailure::None;
    [[nodiscard]] bool operator==(const DelegationReply&) const = default;
};

// Revisions are the one-based ordinal of client NetworkMap frames in this ordered
// authenticated session. The ACK is emitted after the delegated node applies that map.
[[nodiscard]] Frame EncodeMapAcknowledgement(std::uint64_t revision);
[[nodiscard]] std::optional<std::uint64_t> DecodeMapAcknowledgement(const Frame& frame);
[[nodiscard]] Frame EncodeDelegation(const DelegationRequest& request);
[[nodiscard]] Frame EncodeDelegation(const DelegationReply& reply);
[[nodiscard]] std::optional<DelegationRequest> DecodeDelegationRequest(const Frame& frame);
[[nodiscard]] std::optional<DelegationReply> DecodeDelegationReply(const Frame& frame);

} // namespace tailgate::hosted
