#include "tailgate/types/netmap/NetworkMap.h"

#include <algorithm>
#include <charconv>
#include <format>
#include <string_view>

#include <boost/algorithm/string/join.hpp>

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

std::optional<std::size_t> NetworkConfig::FindRoute(std::uint32_t destination,
                                                    std::optional<std::size_t> exitNode) const
{
    std::optional<std::size_t> result;
    int bestPrefixLength = -1;
    for (std::size_t index = 0; index < m_peers.size(); ++index)
    {
        for (const tailgate::net::packet::Ipv4Prefix& prefix : m_peers[index].AllowedPrefixes())
        {
            if (prefix.PrefixLength() == 0 && exitNode != index)
            {
                continue;
            }
            if (prefix.Contains(destination) && prefix.PrefixLength() > bestPrefixLength)
            {
                result = index;
                bestPrefixLength = prefix.PrefixLength();
            }
        }
    }
    if (result)
    {
        return result;
    }
    if (exitNode && *exitNode < m_peers.size() && m_peers[*exitNode].ExitNodeOption())
    {
        return exitNode;
    }
    return std::nullopt;
}

std::optional<std::size_t> NetworkConfig::FindExitNode(const std::string& nameOrAddress,
                                                       bool requireOnline) const
{
    for (std::size_t index = 0; index < m_peers.size(); ++index)
    {
        const PeerConfig& peer = m_peers[index];
        if (requireOnline && !peer.Online())
        {
            continue;
        }
        if (peer.ExitNodeOption() && peer.MatchesTarget(nameOrAddress))
        {
            return index;
        }
    }
    return std::nullopt;
}

bool PeerConfig::MatchesTarget(const std::string& nameOrAddress) const
{
    std::string target = nameOrAddress;
    if (!target.empty() && target.back() == '.')
    {
        target.pop_back();
    }
    std::string name = m_name;
    if (!name.empty() && name.back() == '.')
    {
        name.pop_back();
    }
    const std::string shortName = name.substr(0, name.find('.'));
    return m_address == target || name == target || shortName == target ||
           std::find(m_addresses.begin(), m_addresses.end(), target) != m_addresses.end();
}

std::optional<std::size_t> NetworkConfig::FindPeer(const std::string& nameOrAddress,
                                                   bool requireOnline) const
{
    for (std::size_t index = 0; index < m_peers.size(); ++index)
    {
        if ((!requireOnline || m_peers[index].Online()) &&
            m_peers[index].MatchesTarget(nameOrAddress))
        {
            return index;
        }
    }
    return std::nullopt;
}

std::string PeerConfig::DisplayName() const
{
    std::string result = m_name;
    if (!result.empty() && result.back() == '.')
    {
        result.pop_back();
    }
    const std::size_t dot = result.find('.');
    result = result.substr(0, dot);
    return result.empty() ? m_address : result;
}

std::string NetworkConfig::DerpCodeForRegion(int region) const
{
    if (region == m_derpRegion && !m_derpCode.empty())
    {
        return m_derpCode;
    }
    const auto peer =
        std::find_if(m_peers.begin(),
                     m_peers.end(),
                     [region](const PeerConfig& value)
                     {
                         return value.DerpRegion() == region && !value.DerpCode().empty();
                     });
    return peer == m_peers.end() ? std::format("derp-{}", region) : peer->DerpCode();
}

bool NetworkConfig::HasCapability(const std::string& capability) const
{
    return std::find(m_capabilities.begin(), m_capabilities.end(), capability) !=
           m_capabilities.end();
}

bool NetworkConfig::AllowsFunnelPort(int port) const
{
    constexpr std::string_view prefix = "https://tailscale.com/cap/funnel-ports";
    for (const std::string& capability : m_capabilities)
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

std::string NetworkConfig::DisplayName() const
{
    PeerConfig self;
    self.Name(m_selfName);
    self.Address(m_selfAddress);
    return self.DisplayName();
}

std::string NetworkConfig::FirstIpv6Address() const
{
    const auto found = std::find_if(m_selfAddresses.begin(),
                                    m_selfAddresses.end(),
                                    [](const std::string& address)
                                    {
                                        return address.find(':') != std::string::npos;
                                    });
    return found == m_selfAddresses.end() ? "" : *found;
}

std::string NetworkConfig::CapabilitySummary() const
{
    return m_capabilities.empty() ? "none" : boost::algorithm::join(m_capabilities, ", ");
}

} // namespace tailgate::types::netmap
