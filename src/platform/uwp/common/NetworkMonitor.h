#pragma once

#include <atomic>
#include <memory>

#include <winrt/Windows.Networking.Connectivity.h>

#include <tailgate/base/EventLoop.h>
#include <tailgate/net/netmon/Monitor.h>

namespace tailgate::uwp
{

class NetworkMonitor final : public net::netmon::Monitor
{
public:
    explicit NetworkMonitor(std::shared_ptr<base::EventLoop> events);
    ~NetworkMonitor() override;
    void ExcludeAddress(std::string address);
    [[nodiscard]] net::netmon::Snapshot Current() override;

private:
    struct State
    {
        std::shared_ptr<base::EventLoop> Events;
        std::atomic_uint64_t Generation = 1;
    };

    std::shared_ptr<State> m_state;
    winrt::Windows::Networking::Connectivity::NetworkInformation::NetworkStatusChanged_revoker
        m_registration;
    net::netmon::Snapshot m_snapshot;
    std::string m_excludedAddress;
};

} // namespace tailgate::uwp
