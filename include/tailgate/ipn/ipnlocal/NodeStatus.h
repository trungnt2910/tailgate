#pragma once

#include <tailgate/Status.h>
#include <tailgate/types/netmap/NetworkMap.h>
#include <tailgate/wgengine/Session.h>

namespace tailgate::ipn::ipnlocal
{

// Portable status reconciliation; persistence and foreground notification belong to the host.
class NodeStatus final
{
public:
    explicit NodeStatus(Status& status);
    void ApplyNetwork(const types::netmap::NetworkConfig& network);
    void UpdatePaths(const wgengine::SessionWaitResult& events,
                     const types::netmap::NetworkConfig& network);
    void UpdateStatistics(const wgengine::Session& session,
                          const types::netmap::NetworkConfig& network);

private:
    Status& m_status;
};

} // namespace tailgate::ipn::ipnlocal
