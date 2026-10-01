#include "tailgate/ipn/ipnlocal/DerpConnections.h"

#include <algorithm>
#include <format>
#include <limits>
#include <utility>

#include <tailgate/base/Logging.h>
#include <tailgate/ipn/ipnlocal/NodeError.h>

namespace tailgate::ipn::ipnlocal
{

DerpConnections::DerpConnections(wgengine::Session& session, DerpTransportFactory& factory)
    : m_session(session), m_factory(factory)
{
}

std::size_t DerpConnections::Ensure(int region, const std::string& host, bool preferred)
{
    auto found = std::find_if(m_entries.begin(),
                              m_entries.end(),
                              [&](const DerpRuntime& derp)
                              {
                                  return derp.Region == region;
                              });
    if (found != m_entries.end())
    {
        return static_cast<std::size_t>(found - m_entries.begin());
    }
    if (region <= 0 || region > std::numeric_limits<std::uint16_t>::max() || host.empty())
    {
        throw NodeError(NodeFailure::InvalidDerpRegion);
    }
    tailgate::base::Log(
        tailgate::base::LogLevel::Info,
        "derp",
        std::format("connecting region={} host={}{}", region, host, preferred ? " preferred" : ""));
    const wgengine::DerpConnectionId connectionId = m_session.AddDerpConnection(
        region, m_factory.Create(region, host, preferred, m_entries.size(), m_enabled));
    const tailgate::hosted::DerpRoute route =
        m_routes.Register(connectionId, static_cast<std::uint16_t>(region));
    m_entries.push_back(DerpRuntime{
        .Region = region,
        .Host = host,
        .Connection = connectionId,
        .Route = route,
    });
    return m_entries.size() - 1;
}

void DerpConnections::ApplyNetworkMap(const types::netmap::NetworkConfig& config)
{
    Ensure(config.DerpRegion(), config.DerpHost(), false);
    for (const auto& peer : config.Peers())
    {
        if (peer.DerpRegion() != 0 && !peer.DerpHost().empty())
        {
            Ensure(peer.DerpRegion(), peer.DerpHost(), false);
        }
    }
}

void DerpConnections::ChangeNetwork(const std::string& networkInterface)
{
    m_factory.SetNetworkInterface(networkInterface);
    for (const auto& entry : m_entries)
    {
        m_session.DerpConnection(entry.Connection).ChangeNetwork(networkInterface);
    }
}

void DerpConnections::SetEnabled(bool enabled)
{
    m_enabled = enabled;
    for (const auto& entry : m_entries)
    {
        m_session.DerpConnection(entry.Connection).SetEnabled(enabled);
    }
}

derp::Connection& DerpConnections::ForRegion(int region)
{
    const auto found = std::ranges::find_if(m_entries,
                                            [region](const DerpRuntime& entry)
                                            {
                                                return entry.Region == region;
                                            });
    if (m_entries.empty())
    {
        throw NodeError(NodeFailure::DerpNotProvisioned);
    }
    return m_session.DerpConnection(found != m_entries.end() ? found->Connection
                                                             : m_entries.front().Connection);
}

derp::Connection* DerpConnections::ForRoute(const hosted::DerpRoute& route)
{
    const auto connection = m_routes.Resolve(route);
    return connection ? &m_session.DerpConnection(*connection) : nullptr;
}

const std::vector<DerpRuntime>& DerpConnections::Entries() const noexcept
{
    return m_entries;
}

} // namespace tailgate::ipn::ipnlocal
