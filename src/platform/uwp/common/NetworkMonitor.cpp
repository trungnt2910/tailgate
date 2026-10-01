#include "NetworkMonitor.h"

#include <algorithm>
#include <utility>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Networking.h>

#include "NetworkAdapter.h"

namespace tailgate::uwp
{
namespace connectivity = winrt::Windows::Networking::Connectivity;

NetworkMonitor::NetworkMonitor(std::shared_ptr<base::EventLoop> events)
    : m_state(std::make_shared<State>())
{
    m_state->Events = std::move(events);
}

NetworkMonitor::~NetworkMonitor()
{
    m_state.reset();
    m_registration.revoke();
}

void NetworkMonitor::ExcludeAddress(std::string address)
{
    m_excludedAddress = std::move(address);
    ++m_state->Generation;
}

net::netmon::Snapshot NetworkMonitor::Current()
{
    if (!m_registration)
    {
        // Do not call the network broker while Windows is activating the VPN plugin.
        // The first snapshot is requested after channel startup. Subscribe before reading
        // it so a concurrent change invalidates the snapshot instead of being lost.
        m_registration = connectivity::NetworkInformation::NetworkStatusChanged(
            winrt::auto_revoke,
            [weak = std::weak_ptr(m_state)](const auto&)
            {
                if (const auto state = weak.lock())
                {
                    ++state->Generation;
                    state->Events->Wake();
                }
            });
    }
    const auto generation = m_state->Generation.load();
    if (generation == m_snapshot.Generation)
    {
        return m_snapshot;
    }
    net::netmon::Snapshot snapshot{.Generation = generation, .Networks = {}};
    std::vector<std::string> candidates;
    try
    {
        candidates = NetworkAdapter::Candidates();
    }
    catch (const NetworkAdapterUnavailable&)
    {
        // An empty snapshot tells Core to suspend outer sockets until connectivity returns.
    }
    for (const auto& candidate : candidates)
    {
        net::netmon::Network network{.Interface = candidate, .Addresses = {}};
        bool excluded = false;
        for (const auto& name : connectivity::NetworkInformation::GetHostNames())
        {
            const auto info = name.IPInformation();
            const auto adapter = info ? info.NetworkAdapter() : nullptr;
            if (!adapter ||
                winrt::to_string(winrt::to_hstring(adapter.NetworkAdapterId())) != candidate)
            {
                continue;
            }
            const auto address = winrt::to_string(name.CanonicalName());
            excluded |= address == m_excludedAddress;
            network.Addresses.push_back(address);
        }
        std::ranges::sort(network.Addresses);
        if (!excluded && !network.Addresses.empty())
        {
            snapshot.Networks.push_back(std::move(network));
        }
    }
    m_snapshot = std::move(snapshot);
    return m_snapshot;
}

} // namespace tailgate::uwp
