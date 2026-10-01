#pragma once

#include <string>

#include <tailgate/base/TimeProvider.h>
#include <tailgate/ipn/ipnlocal/NodeBackend.h>
#include <tailgate/serve/FunnelConfig.h>

#include "event/EventRegistry.h"

#include "HostedConnectionRegistry.h"
#include "ModeControl.h"
#include "State.h"

namespace tailgate::linux_frontend
{

struct NodeHostOptions
{
    std::string InterfaceName = "tailgate0";
    std::string UnderlayInterface;
    bool AcceptDns = true;
    serve::FunnelConfig Funnel;
    std::string CertificatePem;
    std::string PrivateKeyPem;
    std::string RelayName;
};

// Linux host effects around the shared node. Packet processing, protocol deadlines,
// map reconciliation and network transport recovery remain in Core.
class NodeHost final
{
public:
    NodeHost(ipn::ipnlocal::NodeBackend& node,
             wgengine::Session& session,
             event::EventRegistry& events,
             HostedConnectionRegistry& hostedConnections,
             base::TimeProvider& time,
             DaemonStatus& status);
    void
    Run(const NodeHostOptions& options, int& readyFd, ModeControl& modes, base::EventLoop& events);

private:
    ipn::ipnlocal::NodeBackend& m_node;
    wgengine::Session& m_session;
    event::EventRegistry& m_events;
    HostedConnectionRegistry& m_hostedConnections;
    base::TimeProvider& m_time;
    DaemonStatus& m_status;
};

} // namespace tailgate::linux_frontend
