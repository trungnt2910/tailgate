#pragma once

#include <tailgate/base/TimeProvider.h>
#include <tailgate/net/netmon/Monitor.h>

namespace tailgate::ipn::ipnlocal
{

struct UnderlayChange
{
    std::uint64_t Generation = 0;
    std::optional<net::netmon::Network> Network;
};

// Platform ranking is a hint. Actual protocol readiness determines whether a candidate
// is usable; a dummy adapter cannot monopolize retries while other candidates exist.
class UnderlaySelection final
{
public:
    explicit UnderlaySelection(base::TimeProvider& time);
    void Start(net::netmon::Snapshot snapshot, const std::optional<std::string>& selected);
    [[nodiscard]] std::optional<UnderlayChange> Poll(net::netmon::Snapshot snapshot, bool ready);

private:
    static constexpr auto ReachabilityTimeout = std::chrono::seconds(15);
    base::TimeProvider& m_time;
    net::netmon::Snapshot m_snapshot;
    std::size_t m_selected = 0;
    std::uint64_t m_generation = 0;
    base::TimeProvider::TimePoint m_deadline{};
};

} // namespace tailgate::ipn::ipnlocal
