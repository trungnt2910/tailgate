#pragma once

#include <tailgate/hosted/Connection.h>
#include <tailgate/ipn/ipnlocal/HostedNode.h>

#include "bg/DI.h"

namespace tailgate::uwp::bg
{

// Owns platform transport dependencies; all relay and packet processing lives in Core.
class HostedConnection final
{
public:
    HostedConnection(PluginInjector injector, tailgate::hosted::Client& client);
    void Start(tailgate::hosted::ConnectionResult connection,
               std::string exitNode,
               std::string relayName);
    [[nodiscard]] tailgate::ipn::ipnlocal::HostedNode& Node() noexcept;
    [[nodiscard]] PacketDevice& Device() noexcept;
    void CancelRecovery();

private:
    PluginInjector m_injector;
    PacketDevice& m_device;
    tailgate::ipn::ipnlocal::HostedNode m_node;
};

} // namespace tailgate::uwp::bg
