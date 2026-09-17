#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <vector>

#include <tailgate/base/TimeProvider.h>
#include <tailgate/wgengine/netstack/Stack.h>

#include "Catalog.h"

namespace tailgate::drive::driveimpl
{

// Single-event-loop, DI-owned pool. Only completely consumed HTTP exchanges may return
// streams here. There is no request replay: a failed write must never duplicate a mutation.
class PeerTransport final
{
public:
    PeerTransport(wgengine::netstack::Stack& stack, base::TimeProvider& time) noexcept;
    ~PeerTransport();
    void SetCatalog(std::shared_ptr<const Catalog> catalog);
    [[nodiscard]] std::unique_ptr<wgengine::netstack::Stream> Acquire(const Remote& remote);
    void Release(const Remote& remote, std::unique_ptr<wgengine::netstack::Stream> stream);
    [[nodiscard]] bool Poll();
    [[nodiscard]] std::optional<base::TimeProvider::TimePoint> NextDeadline() const;
    void Stop() noexcept;

private:
    struct IdleConnection
    {
        Remote Peer;
        std::unique_ptr<wgengine::netstack::Stream> Stream;
        base::TimeProvider::TimePoint Deadline;
    };

    [[nodiscard]] bool Allowed(const Remote& remote) const;
    [[nodiscard]] static bool Healthy(wgengine::netstack::Stream& stream) noexcept;
    static void Close(wgengine::netstack::Stream& stream) noexcept;

    static constexpr std::size_t MaximumIdleConnections = 16;
    static constexpr std::size_t MaximumIdlePerPeer = 2;
    static constexpr auto IdleTimeout = std::chrono::seconds(60);
    wgengine::netstack::Stack& m_stack;
    base::TimeProvider& m_time;
    std::shared_ptr<const Catalog> m_catalog;
    std::vector<IdleConnection> m_idle;
};

} // namespace tailgate::drive::driveimpl
