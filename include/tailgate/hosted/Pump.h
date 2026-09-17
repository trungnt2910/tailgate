#pragma once

#include <chrono>
#include <cstdint>
#include <exception>
#include <optional>
#include <span>

#include <tailgate/hosted/Protocol.h>

namespace tailgate::hosted
{

inline constexpr std::chrono::milliseconds MaximumPumpDelay = std::chrono::minutes(1);
// Bound callback amplification without tying TCP progress to the idle heartbeat cadence.
inline constexpr std::chrono::milliseconds MinimumPumpInterval{5};

struct PumpSchedule
{
    std::uint64_t RequestId = 0;
    std::optional<std::chrono::milliseconds> Delay;
};

enum class PumpError
{
    InvalidMessage,
    RequestIdExhausted,
};

class PumpException final : public std::exception
{
public:
    explicit PumpException(PumpError error) noexcept;
    [[nodiscard]] PumpError Error() const noexcept;
    [[nodiscard]] const char* what() const noexcept override;

private:
    PumpError m_error;
};

[[nodiscard]] std::optional<PumpSchedule>
TryDecodePumpSchedule(std::span<const std::uint8_t> payload) noexcept;
[[nodiscard]] Frame EncodePumpSchedule(const PumpSchedule& schedule);
[[nodiscard]] std::optional<std::uint64_t>
TryDecodePumpReply(std::span<const std::uint8_t> payload) noexcept;
[[nodiscard]] Frame EncodePumpReply(std::uint64_t requestId);

} // namespace tailgate::hosted
