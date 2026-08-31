#pragma once

#include <string>
#include <vector>

#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::wgengine::router
{

struct ConfigOptions
{
    std::vector<tailgate::net::packet::Ipv4Prefix> AdditionalRoutes;
    bool RouteAllTraffic = false;
};

class Config final
{
public:
    [[nodiscard]] static Config Build(const tailgate::types::netmap::NetworkConfig& networkMap,
                                      const ConfigOptions& options = {});

    [[nodiscard]] bool operator==(const Config&) const = default;

    [[nodiscard]] const std::vector<std::string>& LocalAddresses() const noexcept;
    [[nodiscard]] const std::vector<tailgate::net::packet::Ipv4Prefix>& Routes() const noexcept;

private:
    std::vector<std::string> m_localAddresses;
    std::vector<tailgate::net::packet::Ipv4Prefix> m_routes;
};

} // namespace tailgate::wgengine::router
