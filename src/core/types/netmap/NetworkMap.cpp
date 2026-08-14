#include <tailgate/types/netmap/NetworkMap.h>

#include <algorithm>
#include <charconv>
#include <format>
#include <string_view>

namespace tailgate::types::netmap
{
namespace
{

bool AllowsPortToken(const std::string& token, int port)
{
    const std::size_t dash = token.find('-');
    int start = 0;
    int end = 0;
    const auto parse = [](std::string_view value, int& out)
    {
        const char* begin = value.data();
        const char* finish = value.data() + value.size();
        const auto parsed = std::from_chars(begin, finish, out);
        return parsed.ec == std::errc{} && parsed.ptr == finish;
    };
    if (dash == std::string::npos)
    {
        return parse(token, start) && start == port;
    }
    return parse(std::string_view(token).substr(0, dash), start) &&
           parse(std::string_view(token).substr(dash + 1), end) && start <= port && port <= end;
}

} // namespace

std::optional<std::size_t> FindRoute(const std::vector<PeerConfig>& peers,
                                     std::uint32_t destination,
                                     std::optional<std::size_t> exitNode)
{
    std::optional<std::size_t> result;
    int bestPrefixLength = -1;
    for (std::size_t index = 0; index < peers.size(); ++index)
    {
        for (const tailgate::net::packet::Ipv4Prefix& prefix : peers[index].AllowedPrefixes)
        {
            if (prefix.PrefixLength == 0 && exitNode != index)
            {
                continue;
            }
            if (tailgate::net::packet::Contains(prefix, destination) &&
                prefix.PrefixLength > bestPrefixLength)
            {
                result = index;
                bestPrefixLength = prefix.PrefixLength;
            }
        }
    }
    if (result)
    {
        return result;
    }
    if (exitNode && *exitNode < peers.size() && peers[*exitNode].ExitNodeOption)
    {
        return exitNode;
    }
    return std::nullopt;
}

std::optional<std::size_t> FindExitNode(const std::vector<PeerConfig>& peers,
                                        const std::string& nameOrAddress,
                                        bool requireOnline)
{
    for (std::size_t index = 0; index < peers.size(); ++index)
    {
        const PeerConfig& peer = peers[index];
        if (requireOnline && !peer.Online)
        {
            continue;
        }
        std::string name = peer.Name;
        if (!name.empty() && name.back() == '.')
        {
            name.pop_back();
        }
        const std::size_t dot = name.find('.');
        const std::string shortName = name.substr(0, dot);
        if (peer.ExitNodeOption &&
            (peer.Address == nameOrAddress || name == nameOrAddress || shortName == nameOrAddress))
        {
            return index;
        }
    }
    return std::nullopt;
}

std::string DerpCode(const NetworkConfig& config, int region)
{
    if (region == config.DerpRegion && !config.DerpCode.empty())
    {
        return config.DerpCode;
    }
    const auto peer = std::find_if(config.Peers.begin(),
                                   config.Peers.end(),
                                   [region](const PeerConfig& value)
                                   {
                                       return value.DerpRegion == region && !value.DerpCode.empty();
                                   });
    return peer == config.Peers.end() ? std::format("derp-{}", region) : peer->DerpCode;
}

bool HasCapability(const NetworkConfig& config, const std::string& capability)
{
    return std::find(config.Capabilities.begin(), config.Capabilities.end(), capability) !=
           config.Capabilities.end();
}

bool AllowsFunnelPort(const NetworkConfig& config, int port)
{
    constexpr std::string_view prefix = "https://tailscale.com/cap/funnel-ports";
    for (const std::string& capability : config.Capabilities)
    {
        if (capability.rfind(std::string(prefix), 0) != 0)
        {
            continue;
        }
        const std::size_t query = capability.find("ports=");
        if (query == std::string::npos)
        {
            continue;
        }
        std::size_t start = query + 6;
        while (start <= capability.size())
        {
            const std::size_t comma = capability.find(',', start);
            const std::string token = capability.substr(
                start, comma == std::string::npos ? std::string::npos : comma - start);
            if (AllowsPortToken(token, port))
            {
                return true;
            }
            if (comma == std::string::npos)
            {
                break;
            }
            start = comma + 1;
        }
    }
    return false;
}

} // namespace tailgate::types::netmap
