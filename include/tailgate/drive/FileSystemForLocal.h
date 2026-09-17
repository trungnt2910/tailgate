#pragma once

#include <memory>
#include <optional>

#include <tailgate/base/TimeProvider.h>
#include <tailgate/types/netmap/NetworkMap.h>
#include <tailgate/wgengine/netstack/Stream.h>

namespace tailgate::drive
{

class FileSystemForLocal
{
public:
    virtual ~FileSystemForLocal();
    virtual void SetNetworkConfig(const types::netmap::NetworkConfig& config) = 0;
    // Connections must come from host-only interception, never a peer/LAN listener.
    virtual void HandleConn(std::unique_ptr<wgengine::netstack::Stream> stream) = 0;
    [[nodiscard]] virtual bool Poll() = 0;
    [[nodiscard]] virtual std::optional<base::TimeProvider::TimePoint> NextDeadline() const = 0;
    virtual void Stop() noexcept = 0;
};

} // namespace tailgate::drive
