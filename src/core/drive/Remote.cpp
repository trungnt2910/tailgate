#include "tailgate/drive/Remote.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <string_view>

namespace tailgate::drive
{
namespace
{

constexpr std::string_view DriveAccess = "drive:access";
constexpr std::string_view DriveSharer = "tailscale.com/cap/drive-sharer";

std::string DnsName(std::string name)
{
    if (name.ends_with('.'))
    {
        name.pop_back();
    }
    for (auto& character : name)
    {
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    }
    return name;
}

bool ValidName(std::string_view name)
{
    return !name.empty() && name != "." && name != ".." &&
           std::ranges::all_of(name,
                               [](unsigned char character)
                               {
                                   return (character <= '\x7f' &&
                                           (std::islower(character) || std::isdigit(character))) ||
                                          character == '-' || character == '.';
                               });
}

std::optional<net::IpAddress> Address(const std::vector<std::string>& addresses,
                                      const std::string& fallback,
                                      net::AddressFamily family)
{
    for (const auto& text : addresses)
    {
        const auto address = net::IpAddress::TryParse(text);
        if (address && address->Family() == family && !address->IsUnspecified())
        {
            return address;
        }
    }
    if (addresses.empty())
    {
        const auto address = net::IpAddress::TryParse(fallback);
        if (address && address->Family() == family && !address->IsUnspecified())
        {
            return address;
        }
    }
    return std::nullopt;
}

} // namespace

std::vector<Remote> DiscoverRemotes(const types::netmap::NetworkConfig& config)
{
    if (!config.HasCapability(std::string(DriveAccess)))
    {
        return {};
    }
    const auto suffix = '.' + DnsName(config.MagicDnsDomain());
    std::map<std::string, Remote> remotes;
    std::set<std::string> ambiguous;
    const bool hasIpv4 =
        Address(config.SelfAddresses(), config.SelfAddress(), net::AddressFamily::Ipv4).has_value();
    const bool hasIpv6 =
        Address(config.SelfAddresses(), config.SelfAddress(), net::AddressFamily::Ipv6).has_value();
    for (const auto& peer : config.Peers())
    {
        if (!peer.Online() || peer.NodeId() == 0 || peer.Key().empty() ||
            std::ranges::find(peer.Capabilities(), DriveSharer) == peer.Capabilities().end())
        {
            continue;
        }
        Remote remote;
        remote.NodeId = peer.NodeId();
        remote.NodeKey = peer.Key();
        remote.Name = DnsName(peer.Name());
        if (suffix.size() > 1 && remote.Name.ends_with(suffix))
        {
            remote.Name.resize(remote.Name.size() - suffix.size());
        }
        if (!ValidName(remote.Name))
        {
            continue;
        }
        if (hasIpv4 && peer.PeerApi4Port() != 0)
        {
            remote.Ipv4 = Address(peer.Addresses(), peer.Address(), net::AddressFamily::Ipv4);
            if (remote.Ipv4)
            {
                remote.PeerApi4Port = peer.PeerApi4Port();
            }
        }
        if (hasIpv6 && peer.PeerApi6Port() != 0)
        {
            remote.Ipv6 = Address(peer.Addresses(), peer.Address(), net::AddressFamily::Ipv6);
            if (remote.Ipv6)
            {
                remote.PeerApi6Port = peer.PeerApi6Port();
            }
        }
        if (!remote.Ipv4 && !remote.Ipv6)
        {
            continue;
        }
        const auto name = remote.Name;
        if (!remotes.emplace(name, std::move(remote)).second)
        {
            ambiguous.insert(name);
        }
    }
    std::vector<Remote> result;
    for (auto& [name, remote] : remotes)
    {
        if (!ambiguous.contains(name))
        {
            result.push_back(std::move(remote));
        }
    }
    return result;
}

} // namespace tailgate::drive
