#include <tailgate/serve/FunnelConfig.h>

#include <format>

namespace tailgate::serve
{
namespace
{

std::string FallbackDnsName(std::string_view fallbackHostname, std::string_view domain)
{
    if (fallbackHostname.empty())
    {
        return {};
    }
    if (domain.empty())
    {
        return std::string(fallbackHostname);
    }
    return std::string(fallbackHostname) + "." + std::string(domain);
}

} // namespace

FunnelConfig TlsTerminatedTcpFunnel(int port, int localPort)
{
    return FunnelConfig{.Port = port, .LocalPort = localPort, .TerminateTls = true};
}

bool IsEnabled(const FunnelConfig& config)
{
    return config.Port > 0 && config.LocalPort > 0 && config.TerminateTls;
}

std::string TargetHostPort(std::string_view host, int port)
{
    return std::format("{}:{}", host, port);
}

std::string HostFromTarget(std::string_view target)
{
    if (target.empty())
    {
        return {};
    }
    if (target.front() == '[')
    {
        const std::size_t bracket = target.find(']');
        if (bracket == std::string_view::npos)
        {
            return {};
        }
        return std::string(target.substr(1, bracket - 1));
    }
    const std::size_t colon = target.rfind(':');
    if (colon == std::string_view::npos)
    {
        return std::string(target);
    }
    if (target.find(':') != colon)
    {
        return {};
    }
    return std::string(target.substr(0, colon));
}

bool HasFunnelForTarget(const FunnelConfig& config,
                        std::string_view selfDnsName,
                        std::string_view fallbackHostname,
                        std::string_view domain,
                        std::string_view target)
{
    if (!IsEnabled(config))
    {
        return false;
    }
    if (!selfDnsName.empty() && target == TargetHostPort(selfDnsName, config.Port))
    {
        return true;
    }
    const std::string fallback = FallbackDnsName(fallbackHostname, domain);
    return !fallback.empty() && target == TargetHostPort(fallback, config.Port);
}

void ApplyToHostInfo(const FunnelConfig& config, tailgate::control::client::HostInfo& host)
{
    host.IngressEnabled = IsEnabled(config);
    host.WireIngress = false;
}

} // namespace tailgate::serve
