#include "tailgate/ipn/ipnlocal/NodeStatus.h"

#include <algorithm>
#include <format>
#include <utility>

#include <tailgate/crypto/PrefixedKey.h>

namespace tailgate::ipn::ipnlocal
{

NodeStatus::NodeStatus(Status& status) : m_status(status)
{
}

void NodeStatus::ApplyNetwork(const types::netmap::NetworkConfig& network)
{
    m_status.BackendState = "Running";
    m_status.Online = true;
    m_status.Address = network.SelfAddress();
    m_status.Domain =
        network.MagicDnsDomain().empty() ? network.Domain() : network.MagicDnsDomain();
    m_status.Hostname = network.DisplayName();
    m_status.Error.clear();
    std::vector<PeerStatus> peers;
    for (const auto& peer : network.Peers())
    {
        if (peer.Name().empty())
        {
            continue;
        }
        const auto previous =
            std::ranges::find(m_status.Peers, peer.Address(), &PeerStatus::Address);
        PeerStatus status = previous == m_status.Peers.end() ? PeerStatus{} : *previous;
        status.Address = peer.Address();
        status.Hostname = peer.DisplayName();
        status.OperatingSystem = peer.OperatingSystem();
        status.Relay =
            peer.DerpCode().empty() ? std::format("derp-{}", peer.DerpRegion()) : peer.DerpCode();
        status.Online = peer.Online();
        status.ExitNodeOption = peer.ExitNodeOption();
        if (!status.Online)
        {
            status.Active = false;
            status.Direct = false;
            status.Endpoint.clear();
            status.TxBytes = 0;
            status.RxBytes = 0;
        }
        peers.push_back(std::move(status));
    }
    m_status.Peers = std::move(peers);
}

void NodeStatus::UpdatePaths(const wgengine::SessionWaitResult& events,
                             const types::netmap::NetworkConfig& network)
{
    for (const auto& peer : network.Peers())
    {
        const auto key = crypto::PrefixedKey::TryParse(peer.Key(), "nodekey:");
        if (!key)
        {
            continue;
        }
        const auto status = std::ranges::find(m_status.Peers, peer.Address(), &PeerStatus::Address);
        if (status == m_status.Peers.end())
        {
            continue;
        }
        for (const auto& event : events.PathEvents)
        {
            if (event.Peer != *key)
            {
                continue;
            }
            status->Direct = event.DirectEndpoint.has_value();
            status->Endpoint =
                event.DirectEndpoint ? event.DirectEndpoint->ToString() : std::string{};
            if (event.DirectEndpoint)
            {
                status->Active = true;
                status->Online = true;
            }
        }
    }
}

void NodeStatus::UpdateStatistics(const wgengine::Session& session,
                                  const types::netmap::NetworkConfig& network)
{
    for (const auto& peer : network.Peers())
    {
        const auto key = crypto::PrefixedKey::TryParse(peer.Key(), "nodekey:");
        const auto stats = key ? session.PeerStats(*key) : std::nullopt;
        const auto status = std::ranges::find(m_status.Peers, peer.Address(), &PeerStatus::Address);
        if (stats && status != m_status.Peers.end() && peer.Online())
        {
            status->Active = stats->WireGuardSession;
            status->TxBytes = stats->TransmittedBytes;
            status->RxBytes = stats->ReceivedBytes;
            status->Direct = stats->DirectEndpoint.has_value();
            status->Endpoint =
                stats->DirectEndpoint ? stats->DirectEndpoint->ToString() : std::string{};
        }
    }
}

} // namespace tailgate::ipn::ipnlocal
