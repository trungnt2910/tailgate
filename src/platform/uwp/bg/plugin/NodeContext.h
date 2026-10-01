#pragma once

#include <string>
#include <string_view>

#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/Connection.h>
#include <tailgate/hosted/Recovery.h>
#include <tailgate/ipn/ipnlocal/DnsForwarder.h>
#include <tailgate/ipn/ipnlocal/LocalServices.h>
#include <tailgate/wgengine/PeerProtocol.h>
#include <tailgate/wgengine/Session.h>
#include <tailgate/wgengine/ping/Tracker.h>

#include "manager/DataPlaneManager.h"
#include "service/ExitNodeService.h"
#include "service/ModeService.h"
#include "service/PingService.h"

namespace tailgate::uwp::bg
{

// Injected node state. Call reset operations only after retiring packet paths and
// stopping their workers; every connection uses the plugin's single object graph.
class NodeContext final
{
public:
    NodeContext(tailgate::ipn::ipnlocal::LocalServices& localServices,
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
                tailgate::hosted::Recovery& recovery);

    [[nodiscard]] bool Matches(std::string_view profileId,
                               const tailgate::wgengine::PeerIdentity& identity) const noexcept;
    // Preserve account state when the profile and keys are unchanged.
    void Configure(std::string profileId, tailgate::wgengine::PeerIdentity identity);
    void ResetTransport();
    void Stop();

    [[nodiscard]] manager::DataPlaneManager& DataPlane() noexcept;
    [[nodiscard]] tailgate::hosted::Client& HostedClient() noexcept;
    [[nodiscard]] tailgate::hosted::Connection& HostedConnection() noexcept;
    [[nodiscard]] service::ExitNodeService& ExitNode() noexcept;
    [[nodiscard]] service::PingService& Pings() noexcept;
    [[nodiscard]] service::ModeService& Modes() noexcept;

private:
    std::string m_profileId;
    tailgate::wgengine::PeerIdentity m_identity;
    tailgate::ipn::ipnlocal::LocalServices& m_localServices;

    manager::DataPlaneManager& m_dataPlane;
    tailgate::hosted::Client& m_hostedClient;
    tailgate::hosted::Connection& m_hostedConnection;
    service::ExitNodeService& m_exitNode;
    service::PingService& m_pings;
    service::ModeService& m_modes;
    tailgate::wgengine::Session& m_session;
    tailgate::wgengine::PeerProtocol& m_protocol;
    tailgate::ipn::ipnlocal::DnsForwarder& m_dns;
    tailgate::wgengine::ping::Tracker& m_tracker;
    tailgate::hosted::Recovery& m_recovery;
};

} // namespace tailgate::uwp::bg
