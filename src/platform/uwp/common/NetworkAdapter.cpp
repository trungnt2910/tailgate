#include "NetworkAdapter.h"

#include <algorithm>
#include <utility>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Networking.h>

namespace tailgate::uwp
{

NetworkAdapterUnavailable::NetworkAdapterUnavailable()
    : std::runtime_error("The selected underlay network adapter is unavailable.")
{
}

NetworkAdapter::NetworkAdapter(const std::optional<std::string>& identifier)
{
    if (!identifier || identifier->empty())
    {
        return;
    }
    // Include local networks even when Windows has not classified them as Internet-connected.
    // Reachability/selection policy belongs to the node, not to this identifier lookup.
    for (const auto& hostname :
         winrt::Windows::Networking::Connectivity::NetworkInformation::GetHostNames())
    {
        const auto info = hostname.IPInformation();
        const auto adapter = info ? info.NetworkAdapter() : nullptr;
        if (adapter &&
            winrt::to_string(winrt::to_hstring(adapter.NetworkAdapterId())) == *identifier)
        {
            m_adapter = adapter;
            return;
        }
    }
    throw NetworkAdapterUnavailable();
}

const winrt::Windows::Networking::Connectivity::NetworkAdapter&
NetworkAdapter::Native() const noexcept
{
    return m_adapter;
}

std::vector<std::string> NetworkAdapter::Candidates()
{
    namespace connectivity = winrt::Windows::Networking::Connectivity;
    std::vector<std::pair<int, std::string>> candidates;
    for (const auto& profile : connectivity::NetworkInformation::GetConnectionProfiles())
    {
        const auto adapter = profile.NetworkAdapter();
        const auto level = profile.GetNetworkConnectivityLevel();
        if (adapter && level != connectivity::NetworkConnectivityLevel::None)
        {
            candidates.emplace_back(
                static_cast<int>(level),
                winrt::to_string(winrt::to_hstring(adapter.NetworkAdapterId())));
        }
    }
    std::stable_sort(candidates.begin(),
                     candidates.end(),
                     [](const auto& left, const auto& right)
                     {
                         return left.first > right.first;
                     });
    std::vector<std::string> result;
    for (const auto& [level, identifier] : candidates)
    {
        if (std::find(result.begin(), result.end(), identifier) == result.end())
        {
            result.push_back(identifier);
        }
    }
    if (result.empty())
    {
        throw NetworkAdapterUnavailable();
    }
    return result;
}

tailgate::net::Ipv4Address NetworkAdapter::Ipv4Address() const
{
    for (const auto& hostname :
         winrt::Windows::Networking::Connectivity::NetworkInformation::GetHostNames())
    {
        const auto info = hostname.IPInformation();
        const auto adapter = info ? info.NetworkAdapter() : nullptr;
        if (!m_adapter || !adapter || adapter.NetworkAdapterId() != m_adapter.NetworkAdapterId())
        {
            continue;
        }
        if (const auto address =
                net::Ipv4Address::TryParse(winrt::to_string(hostname.CanonicalName()));
            address && address->HostOrder() != 0)
        {
            return *address;
        }
    }
    throw NetworkAdapterUnavailable();
}

} // namespace tailgate::uwp
