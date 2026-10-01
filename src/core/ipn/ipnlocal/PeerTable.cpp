#include "tailgate/ipn/ipnlocal/PeerTable.h"

#include <algorithm>
#include <format>
#include <utility>

#include <tailgate/base/Logging.h>
#include <tailgate/crypto/PrefixedKey.h>
#include <tailgate/wgengine/magicsock/PeerPathState.h>

namespace tailgate::ipn::ipnlocal
{

using TailPeer = types::netmap::PeerConfig;

PeerTable::PeerTable(
    std::optional<std::reference_wrapper<wgengine::magicsock::Connection>> delegatedTransport)
    : m_delegatedTransport(delegatedTransport)
{
}

std::optional<PeerRuntime> PeerTable::BuildPeer(const TailPeer& config)
{
    const auto publicKey = crypto::PrefixedKey::TryParse(config.Key(), "nodekey:");
    if (!publicKey || (m_delegatedTransport && !m_delegatedTransport->get().AddPeer(*publicKey)))
    {
        return std::nullopt;
    }
    PeerRuntime runtime;
    runtime.Config = config;
    runtime.PublicKey = *publicKey;
    UpdateDiscoKey(runtime);
    return runtime;
}

void PeerTable::UpdateDiscoKey(PeerRuntime& peer)
{
    const auto key = crypto::PrefixedKey::TryParse(peer.Config.DiscoKey(), "discokey:");
    peer.HasDiscoKey = key.has_value();
    peer.DiscoPublicKey = key.value_or(crypto::Bytes32{});
}

void PeerTable::Apply(const std::vector<TailPeer>& configs)
{
    for (const TailPeer& configPeer : configs)
    {
        auto existing = std::find_if(m_peers.begin(),
                                     m_peers.end(),
                                     [&](const PeerRuntime& peer)
                                     {
                                         return (configPeer.NodeId() != 0 &&
                                                 peer.Config.NodeId() == configPeer.NodeId()) ||
                                                peer.Config.Address() == configPeer.Address();
                                     });
        if (existing == m_peers.end())
        {
            std::optional<PeerRuntime> runtime = BuildPeer(configPeer);
            if (!runtime)
            {
                continue;
            }
            m_peers.push_back(std::move(*runtime));
            tailgate::base::Log(
                tailgate::base::LogLevel::Info,
                "control",
                std::format("added peer from network-map update: {} version={} ingress={} "
                            "wire-ingress={} peerapi4={} peerapi6={}",
                            configPeer.Name(),
                            configPeer.ClientVersion(),
                            configPeer.IngressEnabled() ? 1 : 0,
                            configPeer.WireIngress() ? 1 : 0,
                            configPeer.PeerApi4Port(),
                            configPeer.PeerApi6Port()));
            continue;
        }

        if (existing->Config.Key() != configPeer.Key())
        {
            tailgate::base::Log(tailgate::base::LogLevel::Info,
                                "control",
                                std::format("peer key generation changed name={} address={} "
                                            "old-node={} new-node={}",
                                            configPeer.Name(),
                                            configPeer.Address(),
                                            existing->Config.NodeId(),
                                            configPeer.NodeId()));
            const auto parsed = crypto::PrefixedKey::TryParse(configPeer.Key(), "nodekey:");
            if (!parsed)
            {
                continue;
            }
            {
                const auto& nextPublicKey = *parsed;
                if (m_delegatedTransport && !m_delegatedTransport->get().AddPeer(nextPublicKey))
                {
                    continue;
                }
                if (m_delegatedTransport)
                {
                    (void)m_delegatedTransport->get().RemovePeer(existing->PublicKey);
                }
                existing->PublicKey = nextPublicKey;
                if (m_delegatedTransport)
                {
                    m_delegatedTransport->get().ResetPath(
                        existing->PublicKey,
                        tailgate::wgengine::magicsock::PeerPathState::ResetMode::
                            ForgetVerifiedEndpoints);
                }
            }
        }
        const bool endpointsChanged = existing->Config.Endpoints() != configPeer.Endpoints();
        const bool discoKeyChanged = existing->Config.DiscoKey() != configPeer.DiscoKey();
        const bool onlineChanged = existing->Config.Online() != configPeer.Online();
        existing->Config = configPeer;
        UpdateDiscoKey(*existing);
        if (onlineChanged || discoKeyChanged || endpointsChanged)
        {
            tailgate::base::Log(tailgate::base::LogLevel::Info,
                                "control",
                                std::format("peer update name={} online={} disco={} endpoints={} "
                                            "version={} ingress={} wire-ingress={} peerapi4={} "
                                            "peerapi6={}",
                                            configPeer.Name(),
                                            configPeer.Online() ? 1 : 0,
                                            existing->HasDiscoKey ? 1 : 0,
                                            configPeer.Endpoints().size(),
                                            configPeer.ClientVersion(),
                                            configPeer.IngressEnabled() ? 1 : 0,
                                            configPeer.WireIngress() ? 1 : 0,
                                            configPeer.PeerApi4Port(),
                                            configPeer.PeerApi6Port()));
        }
        if (m_delegatedTransport && (!configPeer.Online() || endpointsChanged))
        {
            m_delegatedTransport->get().ResetPath(
                existing->PublicKey,
                !configPeer.Online() || discoKeyChanged
                    ? tailgate::wgengine::magicsock::PeerPathState::ResetMode::
                          ForgetVerifiedEndpoints
                    : tailgate::wgengine::magicsock::PeerPathState::ResetMode::
                          PreserveVerifiedEndpoints);
        }
    }
    std::erase_if(
        m_peers,
        [&](const PeerRuntime& peer)
        {
            const bool stillPresent =
                std::ranges::any_of(configs,
                                    [&](const TailPeer& configPeer)
                                    {
                                        return (configPeer.NodeId() != 0 &&
                                                peer.Config.NodeId() == configPeer.NodeId()) ||
                                               peer.Config.Address() == configPeer.Address();
                                    });
            if (!stillPresent)
            {
                base::Log(base::LogLevel::Info,
                          "control",
                          std::format("peer generation removed name={} address={} node={}",
                                      peer.Config.Name(),
                                      peer.Config.Address(),
                                      peer.Config.NodeId()));
                if (m_delegatedTransport)
                {
                    (void)m_delegatedTransport->get().RemovePeer(peer.PublicKey);
                }
            }
            return !stillPresent;
        });
    std::vector<TailPeer> routable;
    routable.reserve(m_peers.size());
    for (const auto& peer : m_peers)
    {
        routable.push_back(peer.Config);
    }
    m_network.Peers(std::move(routable));
}

std::deque<PeerRuntime>& PeerTable::Entries() noexcept
{
    return m_peers;
}

const types::netmap::NetworkConfig& PeerTable::Network() const noexcept
{
    return m_network;
}

PeerRuntime* PeerTable::FindKey(const crypto::Bytes32& key)
{
    const auto found = std::ranges::find(m_peers, key, &PeerRuntime::PublicKey);
    return found == m_peers.end() ? nullptr : &*found;
}

PeerRuntime* PeerTable::FindDiscoKey(const crypto::Bytes32& key)
{
    const auto found =
        std::ranges::find_if(m_peers,
                             [&](const PeerRuntime& peer)
                             {
                                 return peer.HasDiscoKey && peer.DiscoPublicKey == key;
                             });
    return found == m_peers.end() ? nullptr : &*found;
}

} // namespace tailgate::ipn::ipnlocal
