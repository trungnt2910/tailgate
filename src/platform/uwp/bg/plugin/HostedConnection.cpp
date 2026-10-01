#include "HostedConnection.h"

#include <utility>

namespace tailgate::uwp::bg
{

HostedConnection::HostedConnection(PluginInjector injector, tailgate::hosted::Client& client)
    : m_injector(std::move(injector)),
      m_device(m_injector->create<PacketDevice&>()),
      m_node(client,
             m_injector->create<tailgate::wgengine::Session&>(),
             m_injector->create<tailgate::wgengine::Engine&>(),
             m_injector->create<tailgate::ipn::ipnlocal::LocalServices&>(),
             m_injector->create<tailgate::ipn::ipnlocal::DnsForwarder&>(),
             m_injector->create<tailgate::wgengine::ping::Tracker&>(),
             m_injector->create<tailgate::base::TimeProvider&>(),
             m_injector->create<tailgate::hosted::Dns&>(),
             m_injector->create<tailgate::hosted::Recovery&>())
{
}

void HostedConnection::Start(tailgate::hosted::ConnectionResult connection,
                             std::string exitNode,
                             std::string relayName)
{
    constexpr tailgate::base::EventToken DeviceToken{.Value = 4};
    m_node.Start(std::move(connection),
                 {.Name = {}, .ReadinessToken = DeviceToken},
                 std::move(exitNode),
                 std::move(relayName));
}

tailgate::ipn::ipnlocal::HostedNode& HostedConnection::Node() noexcept
{
    return m_node;
}

void HostedConnection::CancelRecovery()
{
    m_injector->create<tailgate::hosted::Recovery&>().Cancel();
}

PacketDevice& HostedConnection::Device() noexcept
{
    return m_device;
}

} // namespace tailgate::uwp::bg
