#include "tailgate/ipn/ipnlocal/NetworkPolicy.h"

#include <utility>

namespace tailgate::ipn::ipnlocal
{

NetworkPolicy::NetworkPolicy(std::string exitNode) : m_exitNode(std::move(exitNode))
{
}

PolicyChange NetworkPolicy::Apply(const types::netmap::NetworkConfig& config)
{
    const auto exitPeer = m_exitNode.empty() ? std::nullopt : config.FindExitNode(m_exitNode, true);
    auto routes = wgengine::router::Config::Build(
        config,
        wgengine::router::ConfigOptions{.AdditionalRoutes = {},
                                        .RouteAllTraffic = exitPeer.has_value()});
    PolicyChange change{
        .PreviousRoutes = m_routes,
        .DnsChanged = m_network.DnsResolver() != config.DnsResolver() ||
                      m_network.DnsDomains() != config.DnsDomains(),
    };
    m_network = config;
    m_routes = std::move(routes);
    m_exitPeer = exitPeer;
    return change;
}

const types::netmap::NetworkConfig& NetworkPolicy::Network() const noexcept
{
    return m_network;
}

const wgengine::router::Config& NetworkPolicy::Routes() const noexcept
{
    return m_routes;
}

std::optional<std::size_t> NetworkPolicy::ExitPeer() const noexcept
{
    return m_exitPeer;
}

} // namespace tailgate::ipn::ipnlocal
