#pragma once

#include <optional>
#include <string>

#include <tailgate/types/netmap/NetworkMap.h>
#include <tailgate/wgengine/router/Config.h>

namespace tailgate::ipn::ipnlocal
{

struct PolicyChange
{
    wgengine::router::Config PreviousRoutes;
    bool DnsChanged = false;
};

class NetworkPolicy final
{
public:
    explicit NetworkPolicy(std::string exitNode);
    [[nodiscard]] PolicyChange Apply(const types::netmap::NetworkConfig& config);
    [[nodiscard]] const types::netmap::NetworkConfig& Network() const noexcept;
    [[nodiscard]] const wgengine::router::Config& Routes() const noexcept;
    [[nodiscard]] std::optional<std::size_t> ExitPeer() const noexcept;

private:
    std::string m_exitNode;
    types::netmap::NetworkConfig m_network;
    wgengine::router::Config m_routes;
    std::optional<std::size_t> m_exitPeer;
};

} // namespace tailgate::ipn::ipnlocal
