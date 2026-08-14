#include <tailgate/wgengine/wireguard/Router.h>

#include <algorithm>
#include <deque>
#include <format>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <tailgate/base/Logging.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/wgengine/wireguard/Tunnel.h>

namespace tailgate::wgengine::wireguard
{

using tailgate::base::Log;
using tailgate::base::LogLevel;
using tailgate::crypto::Bytes32;
using tailgate::crypto::HexToBytes;

namespace
{

constexpr std::size_t MaximumPendingPacketsPerPeer = 1024;
constexpr std::size_t MaximumPendingBytesPerPeer = 4U * 1024U * 1024U;

Bytes32 ParseNodeKey(const std::string& text)
{
    constexpr std::string_view Prefix = "nodekey:";
    if (text.rfind(Prefix, 0) != 0)
    {
        throw std::invalid_argument("Invalid node key prefix.");
    }
    const std::vector<std::uint8_t> bytes = HexToBytes(text.substr(Prefix.size()));
    if (bytes.size() != Bytes32{}.size())
    {
        throw std::invalid_argument("Invalid node key length.");
    }
    Bytes32 result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

} // namespace

class WireGuardRouter::Impl
{
public:
    struct Peer
    {
        tailgate::types::netmap::PeerConfig Config;
        Bytes32 PublicKey{};
        WireGuardTunnel::PeerId TunnelPeer = 0;
        bool Active = true;
        std::deque<std::vector<std::uint8_t>> Pending;
        std::size_t PendingBytes = 0;
    };

    Impl(const Bytes32& privateKey,
         const std::vector<tailgate::types::netmap::PeerConfig>& peers,
         std::string exitNode)
        : Tunnel(privateKey), ExitNode(std::move(exitNode))
    {
        UpdatePeers(peers, ExitNode);
    }

    void UpdatePeers(const std::vector<tailgate::types::netmap::PeerConfig>& configs,
                     std::string exitNode)
    {
        ExitNode = std::move(exitNode);
        for (Peer& peer : Peers)
        {
            peer.Active = false;
        }
        Routes.clear();
        for (const tailgate::types::netmap::PeerConfig& config : configs)
        {
            Bytes32 publicKey{};
            try
            {
                publicKey = ParseNodeKey(config.Key);
            }
            catch (const std::exception&)
            {
                Log(LogLevel::Warning, "wireguard", "ignoring peer with invalid node key");
                continue;
            }
            auto found = std::find_if(Peers.begin(),
                                      Peers.end(),
                                      [&](const Peer& peer)
                                      {
                                          return peer.PublicKey == publicKey;
                                      });
            if (found == Peers.end())
            {
                Peer peer;
                peer.Config = config;
                peer.PublicKey = publicKey;
                peer.TunnelPeer = Tunnel.AddPeer(publicKey, {}, 10, true);
                Peers.push_back(std::move(peer));
                found = std::prev(Peers.end());
            }
            else
            {
                found->Config = config;
                found->Active = true;
            }
            Routes.push_back(&*found);
        }
    }

    Peer* FindRoute(const std::vector<std::uint8_t>& packet)
    {
        const std::optional<std::uint32_t> destination =
            tailgate::net::packet::Ipv4Destination(packet);
        if (!destination)
        {
            return nullptr;
        }
        std::vector<tailgate::types::netmap::PeerConfig> configs;
        configs.reserve(Routes.size());
        for (const Peer* peer : Routes)
        {
            configs.push_back(peer->Config);
        }
        const std::optional<std::size_t> exit =
            ExitNode.empty() ? std::nullopt
                             : tailgate::types::netmap::FindExitNode(configs, ExitNode, true);
        const std::optional<std::size_t> route =
            tailgate::types::netmap::FindRoute(configs, *destination, exit);
        return route ? Routes[*route] : nullptr;
    }

    Peer* FindPeer(const Bytes32& key)
    {
        const auto found = std::find_if(Peers.begin(),
                                        Peers.end(),
                                        [&](const Peer& peer)
                                        {
                                            return peer.Active && peer.PublicKey == key;
                                        });
        return found == Peers.end() ? nullptr : &*found;
    }

    void Queue(Peer& peer, std::vector<std::uint8_t> plaintext)
    {
        while (!peer.Pending.empty() &&
               (peer.Pending.size() >= MaximumPendingPacketsPerPeer ||
                peer.PendingBytes + plaintext.size() > MaximumPendingBytesPerPeer))
        {
            peer.PendingBytes -= peer.Pending.front().size();
            peer.Pending.pop_front();
            Log(LogLevel::Warning,
                "wireguard",
                "pending plaintext queue limit reached peer=" + peer.Config.Name);
        }
        if (plaintext.size() <= MaximumPendingBytesPerPeer)
        {
            peer.PendingBytes += plaintext.size();
            peer.Pending.push_back(std::move(plaintext));
        }
    }

    TransportPacket Wrap(const Peer& peer, std::vector<std::uint8_t> payload, bool control) const
    {
        return TransportPacket{
            .Peer = peer.PublicKey, .Payload = std::move(payload), .Control = control};
    }

    std::vector<TransportPacket> Flush(Peer& peer)
    {
        std::vector<TransportPacket> result;
        while (Tunnel.HasSession(peer.TunnelPeer) && !peer.Pending.empty())
        {
            std::vector<std::uint8_t> plaintext = std::move(peer.Pending.front());
            peer.Pending.pop_front();
            peer.PendingBytes -= plaintext.size();
            result.push_back(Wrap(peer, Tunnel.Encrypt(peer.TunnelPeer, plaintext), false));
        }
        return result;
    }

    WireGuardTunnel Tunnel;
    std::deque<Peer> Peers;
    std::vector<Peer*> Routes;
    std::set<std::pair<unsigned, std::uint32_t>> ReportedUnroutableDestinations;
    std::string ExitNode;
};

WireGuardRouter::WireGuardRouter(const Bytes32& nodePrivateKey,
                                 const std::vector<tailgate::types::netmap::PeerConfig>& peers,
                                 std::string exitNode)
    : m_impl(std::make_unique<Impl>(nodePrivateKey, peers, std::move(exitNode)))
{
}

WireGuardRouter::~WireGuardRouter() = default;
WireGuardRouter::WireGuardRouter(WireGuardRouter&&) noexcept = default;
WireGuardRouter& WireGuardRouter::operator=(WireGuardRouter&&) noexcept = default;

void WireGuardRouter::UpdatePeers(const std::vector<tailgate::types::netmap::PeerConfig>& peers,
                                  std::string exitNode)
{
    m_impl->UpdatePeers(peers, std::move(exitNode));
}

std::vector<WireGuardRouter::TransportPacket>
WireGuardRouter::Send(const std::vector<std::uint8_t>& plaintext)
{
    Impl::Peer* peer = m_impl->FindRoute(plaintext);
    if (peer == nullptr)
    {
        const std::optional<std::uint32_t> destination =
            tailgate::net::packet::Ipv4Destination(plaintext);
        const unsigned version = plaintext.empty() ? 0U : plaintext.front() >> 4U;
        if (m_impl->ReportedUnroutableDestinations.emplace(version, destination.value_or(0)).second)
        {
            Log(LogLevel::Warning,
                "wireguard",
                std::format("dropping plaintext packet without a peer route destination={} "
                            "version={} bytes={}",
                            destination ? tailgate::net::packet::FormatIpv4(*destination)
                                        : "non-ipv4",
                            version,
                            plaintext.size()));
        }
        return {};
    }
    if (m_impl->Tunnel.HasSession(peer->TunnelPeer))
    {
        return {m_impl->Wrap(*peer, m_impl->Tunnel.Encrypt(peer->TunnelPeer, plaintext), false)};
    }
    m_impl->Queue(*peer, plaintext);
    if (m_impl->Tunnel.UpdateTimers(peer->TunnelPeer) ==
        WireGuardTunnel::TimerAction::SendHandshake)
    {
        return {m_impl->Wrap(*peer, m_impl->Tunnel.CreateHandshake(peer->TunnelPeer), true)};
    }
    return {};
}

WireGuardRouter::ReceiveResult WireGuardRouter::Receive(const Bytes32& source,
                                                        const std::vector<std::uint8_t>& packet)
{
    ReceiveResult result;
    Impl::Peer* peer = m_impl->FindPeer(source);
    if (peer == nullptr)
    {
        Log(LogLevel::Warning, "wireguard", "dropping transport packet from unknown peer");
        return result;
    }
    const std::optional<WireGuardTunnel::ReceivedPacket> received =
        m_impl->Tunnel.ProcessPacket(peer->TunnelPeer, packet);
    if (!received)
    {
        const unsigned type = packet.empty() ? 0U : packet.front();
        Log(LogLevel::Debug,
            "wireguard",
            std::format("rejected transport packet peer={} type={} bytes={}",
                        peer->Config.Name,
                        type,
                        packet.size()));
        return result;
    }
    if (!received->Reply.empty())
    {
        result.Outbound.push_back(m_impl->Wrap(*peer, received->Reply, true));
    }
    if (received->SessionEstablished)
    {
        Log(LogLevel::Debug, "wireguard", "session established peer=" + peer->Config.Name);
        std::vector<TransportPacket> pending = m_impl->Flush(*peer);
        result.Outbound.insert(result.Outbound.end(),
                               std::make_move_iterator(pending.begin()),
                               std::make_move_iterator(pending.end()));
    }
    if (!received->Plaintext.empty())
    {
        result.Plaintext.push_back(received->Plaintext);
    }
    return result;
}

std::vector<WireGuardRouter::TransportPacket> WireGuardRouter::UpdateTimers()
{
    std::vector<TransportPacket> result;
    for (Impl::Peer* peer : m_impl->Routes)
    {
        const WireGuardTunnel::TimerAction action = m_impl->Tunnel.UpdateTimers(peer->TunnelPeer);
        if (action == WireGuardTunnel::TimerAction::SendHandshake)
        {
            result.push_back(
                m_impl->Wrap(*peer, m_impl->Tunnel.CreateHandshake(peer->TunnelPeer), true));
        }
        else if (action == WireGuardTunnel::TimerAction::SendKeepalive)
        {
            result.push_back(
                m_impl->Wrap(*peer, m_impl->Tunnel.Encrypt(peer->TunnelPeer, {}), true));
        }
    }
    return result;
}

} // namespace tailgate::wgengine::wireguard
