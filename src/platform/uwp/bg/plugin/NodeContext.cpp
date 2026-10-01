#include "NodeContext.h"

#include <utility>

namespace tailgate::uwp::bg
{

NodeContext::NodeContext(tailgate::ipn::ipnlocal::LocalServices& localServices,
                         manager::DataPlaneManager& dataPlane,
                         tailgate::hosted::Client& hostedClient,
                         tailgate::hosted::Connection& hostedConnection,
                         service::ExitNodeService& exitNode,
                         service::PingService& pings,
                         service::ModeService& modes,
                         tailgate::wgengine::Session& session,
                         tailgate::wgengine::PeerProtocol& protocol,
                         tailgate::ipn::ipnlocal::DnsForwarder& dns,
                         tailgate::wgengine::ping::Tracker& tracker,
                         tailgate::hosted::Recovery& recovery)
    : m_localServices(localServices),
      m_dataPlane(dataPlane),
      m_hostedClient(hostedClient),
      m_hostedConnection(hostedConnection),
      m_exitNode(exitNode),
      m_pings(pings),
      m_modes(modes),
      m_session(session),
      m_protocol(protocol),
      m_dns(dns),
      m_tracker(tracker),
      m_recovery(recovery)
{
}

void NodeContext::Configure(std::string profileId, tailgate::wgengine::PeerIdentity identity)
{
    if (Matches(profileId, identity))
    {
        return;
    }
    Stop();
    ResetTransport();
    m_protocol.Reset();
    m_dns.Reset();
    m_tracker.Reset();
    m_profileId = std::move(profileId);
    m_identity = std::move(identity);
}

void NodeContext::ResetTransport()
{
    m_hostedClient.Stop();
    m_recovery.Reset();
    m_session.Reset();
    m_dataPlane.Reset();
}

void NodeContext::Stop()
{
    m_hostedClient.Stop();
    m_localServices.Stop();
    m_dataPlane.Stop();
}

bool NodeContext::Matches(std::string_view profileId,
                          const tailgate::wgengine::PeerIdentity& identity) const noexcept
{
    return m_profileId == profileId && m_identity == identity;
}

manager::DataPlaneManager& NodeContext::DataPlane() noexcept
{
    return m_dataPlane;
}

tailgate::hosted::Client& NodeContext::HostedClient() noexcept
{
    return m_hostedClient;
}

tailgate::hosted::Connection& NodeContext::HostedConnection() noexcept
{
    return m_hostedConnection;
}

service::ExitNodeService& NodeContext::ExitNode() noexcept
{
    return m_exitNode;
}

service::PingService& NodeContext::Pings() noexcept
{
    return m_pings;
}

service::ModeService& NodeContext::Modes() noexcept
{
    return m_modes;
}

} // namespace tailgate::uwp::bg
