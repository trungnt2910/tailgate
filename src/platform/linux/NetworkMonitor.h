#pragma once

#include <tailgate/net/netmon/Monitor.h>

#include "UniqueFd.h"
#include "event/EventRegistry.h"

namespace tailgate::linux_frontend
{

class NetworkMonitor final : public net::netmon::Monitor
{
public:
    NetworkMonitor(event::EventRegistry& events, std::string excludedInterface);
    [[nodiscard]] net::netmon::Snapshot Current() override;
    void ProcessEvent(const base::Event& event);

private:
    std::string m_excludedInterface;
    UniqueFd m_socket;
    event::EventHandle m_registration;
    net::netmon::Snapshot m_snapshot;
    bool m_dirty = true;
};

} // namespace tailgate::linux_frontend
