#include "tailgate/hosted/Pump.h"

#include <climits>
#include <cstddef>
#include <limits>
#include <vector>

namespace tailgate::hosted
{
namespace
{

constexpr std::size_t RequestIdSize = sizeof(std::uint64_t);
constexpr std::size_t DelaySize = sizeof(std::uint32_t);
constexpr std::size_t ScheduleSize = RequestIdSize + DelaySize;
constexpr std::uint32_t CancelDeadline = std::numeric_limits<std::uint32_t>::max();

std::uint64_t DecodeInteger(std::span<const std::uint8_t> bytes) noexcept
{
    std::uint64_t value = 0;
    for (const auto byte : bytes)
    {
        value = (value << CHAR_BIT) | byte;
    }
    return value;
}

void EncodeInteger(std::span<std::uint8_t> bytes, std::uint64_t value) noexcept
{
    for (auto byte = bytes.rbegin(); byte != bytes.rend(); ++byte)
    {
        *byte = static_cast<std::uint8_t>(value);
        value >>= CHAR_BIT;
    }
}

} // namespace

PumpException::PumpException(PumpError error) noexcept : m_error(error)
{
}

PumpError PumpException::Error() const noexcept
{
    return m_error;
}

const char* PumpException::what() const noexcept
{
    return m_error == PumpError::InvalidMessage ? "invalid hosted pump message"
                                                : "hosted pump request identifiers exhausted";
}

std::optional<PumpSchedule> TryDecodePumpSchedule(std::span<const std::uint8_t> payload) noexcept
{
    if (payload.size() != ScheduleSize)
    {
        return std::nullopt;
    }
    const auto id = DecodeInteger(payload.first(RequestIdSize));
    const auto delay = DecodeInteger(payload.subspan(RequestIdSize));
    if (id == 0 ||
        (delay != CancelDeadline && delay > static_cast<std::uint64_t>(MaximumPumpDelay.count())))
    {
        return std::nullopt;
    }
    PumpSchedule result;
    result.RequestId = id;
    if (delay != CancelDeadline)
    {
        result.Delay = std::chrono::milliseconds(delay);
    }
    return result;
}

Frame EncodePumpSchedule(const PumpSchedule& schedule)
{
    if (schedule.RequestId == 0 ||
        (schedule.Delay && (*schedule.Delay < std::chrono::milliseconds::zero() ||
                            *schedule.Delay > MaximumPumpDelay)))
    {
        throw PumpException(PumpError::InvalidMessage);
    }
    std::vector<std::uint8_t> payload(ScheduleSize);
    EncodeInteger(std::span(payload).first(RequestIdSize), schedule.RequestId);
    EncodeInteger(std::span(payload).subspan(RequestIdSize),
                  schedule.Delay ? static_cast<std::uint64_t>(schedule.Delay->count())
                                 : CancelDeadline);
    return Frame(MessageType::PumpSchedule, std::move(payload));
}

std::optional<std::uint64_t> TryDecodePumpReply(std::span<const std::uint8_t> payload) noexcept
{
    if (payload.size() != RequestIdSize)
    {
        return std::nullopt;
    }
    const auto id = DecodeInteger(payload);
    return id == 0 ? std::nullopt : std::optional(id);
}

Frame EncodePumpReply(std::uint64_t requestId)
{
    if (requestId == 0)
    {
        throw PumpException(PumpError::InvalidMessage);
    }
    std::vector<std::uint8_t> payload(RequestIdSize);
    EncodeInteger(payload, requestId);
    return Frame(MessageType::Pump, std::move(payload));
}

} // namespace tailgate::hosted
