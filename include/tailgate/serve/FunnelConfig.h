#pragma once

#include "tailgate/protocol/ControlRequests.h"

#include <string>
#include <string_view>

namespace tailgate::serve
{

struct FunnelConfig
{
    int Port = 0;
    int LocalPort = 0;
    bool TerminateTls = false;
};

[[nodiscard]] FunnelConfig TlsTerminatedTcpFunnel(int port, int localPort);
[[nodiscard]] bool IsEnabled(const FunnelConfig& config);
[[nodiscard]] std::string TargetHostPort(std::string_view host, int port);
[[nodiscard]] std::string HostFromTarget(std::string_view target);
[[nodiscard]] bool HasFunnelForTarget(const FunnelConfig& config,
                                      std::string_view selfDnsName,
                                      std::string_view fallbackHostname,
                                      std::string_view domain,
                                      std::string_view target);
void ApplyToHostInfo(const FunnelConfig& config, protocol::HostInfo& host);

} // namespace tailgate::serve
