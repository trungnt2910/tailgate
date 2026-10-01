#pragma once

#include <tailgate/hosted/Connection.h>
#include <tailgate/ipn/ipnlocal/SwitchingNode.h>

#include "State.h"

namespace tailgate::linux_frontend
{

// Adapts a signalled preferences reload to the shared mode transaction.
class ModeControl final
{
public:
    ModeControl(ipn::ipnlocal::SwitchingNode& node, hosted::ConnectionOptions options);
    [[nodiscard]] bool Reload();
    [[nodiscard]] bool UpdateStatus(DaemonStatus& status);
    void ChangeNetwork(std::optional<std::string> networkInterface);
    void SetStunServer(std::optional<net::Endpoint> endpoint);
    [[nodiscard]] bool TransportReady() const;

private:
    ipn::ipnlocal::SwitchingNode& m_node;
    hosted::ConnectionOptions m_options;
    std::optional<SettingsState> m_settings;
    std::optional<ipn::ipnlocal::TransitionStatus> m_reported;
};

} // namespace tailgate::linux_frontend
