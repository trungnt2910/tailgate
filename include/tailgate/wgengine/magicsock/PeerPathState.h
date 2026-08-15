#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/base/Clock.h>

namespace tailgate::wgengine::magicsock
{

struct Endpoint
{
    std::uint32_t Address = 0;
    std::uint16_t Port = 0;

    [[nodiscard]] bool operator==(const Endpoint&) const = default;
};

class PeerPathState final
{
public:
    using TimePoint = tailgate::base::IClock::TimePoint;

    enum class ResetMode
    {
        PreserveVerifiedEndpoints,
        ForgetVerifiedEndpoints,
    };

    static constexpr std::size_t MaximumVerifiedEndpoints = 32;
    static constexpr auto DirectProbeInterval = std::chrono::seconds(5);
    static constexpr auto DirectPathTimeout = std::chrono::seconds(15);

    [[nodiscard]] bool HasDirectPath() const noexcept;
    [[nodiscard]] const std::optional<Endpoint>& DirectEndpoint() const noexcept;
    [[nodiscard]] bool IsVerified(const Endpoint& endpoint) const noexcept;

    [[nodiscard]] bool TryBeginProbe(TimePoint now) noexcept;
    [[nodiscard]] bool MarkDirect(const Endpoint& endpoint);
    void MarkDirectSend(TimePoint now) noexcept;
    void MarkDirectReceive() noexcept;
    [[nodiscard]] bool ExpireDirectPath(TimePoint now) noexcept;
    void Reset(ResetMode mode) noexcept;

private:
    void RememberVerified(const Endpoint& endpoint);

    std::optional<Endpoint> m_directEndpoint;
    std::vector<Endpoint> m_verifiedEndpoints;
    std::optional<TimePoint> m_lastDirectProbe;
    std::optional<TimePoint> m_firstUnansweredDirectSend;
};

} // namespace tailgate::wgengine::magicsock
