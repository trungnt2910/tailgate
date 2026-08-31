#include "ConnectionImpl.h"

#include <algorithm>
#include <utility>

namespace tailgate::wgengine::magicsock::impl
{

ConnectionImpl::ConnectionImpl(tailgate::types::nettype::UdpSocketFactory& socketFactory,
                               tailgate::base::TimeProvider& timeProvider) noexcept
    : m_socketFactory(socketFactory), m_timeProvider(timeProvider)
{
}

ConnectionImpl::~ConnectionImpl()
{
    Close();
}

bool ConnectionImpl::Open(const tailgate::types::nettype::UdpSocketOptions& options)
{
    if (m_socket)
    {
        return false;
    }
    m_socket = m_socketFactory.OpenUdpSocket(options);
    if (!m_socket)
    {
        return false;
    }
    m_readinessToken = options.ReadinessToken;
    m_logger.LogDebug("opened UDP socket port={}", m_socket->LocalEndpoint().Port());
    return true;
}

bool ConnectionImpl::AddPeer(const tailgate::crypto::Bytes32& peer)
{
    const auto [_, inserted] = m_peers.emplace(peer, PeerState{});
    if (inserted)
    {
        m_logger.LogDebug("added peer state peer={}", tailgate::crypto::BytesToHex(peer.data(), 8));
    }
    return inserted;
}

bool ConnectionImpl::RemovePeer(const tailgate::crypto::Bytes32& peer)
{
    if (m_peers.erase(peer) == 0)
    {
        return false;
    }
    UpdateWriteInterest();
    m_logger.LogDebug("removed peer state peer={}", tailgate::crypto::BytesToHex(peer.data(), 8));
    return true;
}

bool ConnectionImpl::HasPeer(const tailgate::crypto::Bytes32& peer) const noexcept
{
    return m_peers.contains(peer);
}

std::optional<tailgate::net::Endpoint> ConnectionImpl::LocalEndpoint() const
{
    return m_socket ? std::optional<tailgate::net::Endpoint>(m_socket->LocalEndpoint())
                    : std::nullopt;
}

std::optional<tailgate::types::nettype::SocketIoResult>
ConnectionImpl::TrySendProbe(const tailgate::net::Endpoint& destination,
                             const std::vector<std::uint8_t>& payload)
{
    if (!m_socket)
    {
        return std::nullopt;
    }
    return m_socket->TrySendTo(destination, payload);
}

std::optional<tailgate::types::nettype::SocketIoResult>
ConnectionImpl::TrySendDirect(const tailgate::crypto::Bytes32& peer,
                              const tailgate::net::Endpoint& destination,
                              const std::vector<std::uint8_t>& payload)
{
    if (!m_socket || !m_peers.contains(peer))
    {
        return std::nullopt;
    }
    return m_socket->TrySendTo(destination, payload);
}

ConnectionImpl::DirectSendResult
ConnectionImpl::SendDirect(const tailgate::crypto::Bytes32& peer,
                           const tailgate::net::Endpoint& destination,
                           const std::vector<std::uint8_t>& payload)
{
    const auto found = m_peers.find(peer);
    if (!m_socket || found == m_peers.end())
    {
        return DirectSendResult::Unavailable;
    }
    PeerState& peerState = found->second;
    if (!peerState.Pending.empty())
    {
        return Queue(peerState, destination, payload) ? DirectSendResult::Queued
                                                      : DirectSendResult::Dropped;
    }
    const tailgate::types::nettype::SocketIoResult sent = m_socket->TrySendTo(destination, payload);
    if (sent == tailgate::types::nettype::SocketIoResult::Complete)
    {
        return DirectSendResult::Sent;
    }
    if (sent == tailgate::types::nettype::SocketIoResult::Closed)
    {
        return DirectSendResult::Unavailable;
    }
    if (sent == tailgate::types::nettype::SocketIoResult::Unavailable)
    {
        return DirectSendResult::Unavailable;
    }
    return Queue(peerState, destination, payload) ? DirectSendResult::Queued
                                                  : DirectSendResult::Dropped;
}

ConnectionImpl::DirectSendResult ConnectionImpl::Send(const tailgate::crypto::Bytes32& peer,
                                                      const std::vector<std::uint8_t>& payload,
                                                      bool expectResponse)
{
    const auto found = m_peers.find(peer);
    if (found == m_peers.end() || !found->second.Path.DirectEndpoint())
    {
        return DirectSendResult::Unavailable;
    }
    const DirectSendResult result = SendDirect(peer, *found->second.Path.DirectEndpoint(), payload);
    if (expectResponse)
    {
        found->second.Path.MarkDirectSend(m_timeProvider.Now());
    }
    return result;
}

bool ConnectionImpl::HasDirectPath(const tailgate::crypto::Bytes32& peer) const noexcept
{
    const auto found = m_peers.find(peer);
    return found != m_peers.end() && found->second.Path.HasDirectPath();
}

std::optional<tailgate::net::Endpoint>
ConnectionImpl::DirectEndpoint(const tailgate::crypto::Bytes32& peer) const noexcept
{
    const auto found = m_peers.find(peer);
    return found == m_peers.end() ? std::nullopt : found->second.Path.DirectEndpoint();
}

std::optional<tailgate::crypto::Bytes32>
ConnectionImpl::AcceptDirectSource(const tailgate::net::Endpoint& endpoint) noexcept
{
    const auto found = std::find_if(m_peers.begin(),
                                    m_peers.end(),
                                    [&](const auto& candidate)
                                    {
                                        return candidate.second.Path.IsVerified(endpoint);
                                    });
    if (found == m_peers.end())
    {
        return std::nullopt;
    }
    found->second.Path.MarkDirectReceive();
    return found->first;
}

bool ConnectionImpl::TryBeginProbe(const tailgate::crypto::Bytes32& peer) noexcept
{
    const auto found = m_peers.find(peer);
    return found != m_peers.end() && found->second.Path.TryBeginProbe(m_timeProvider.Now());
}

bool ConnectionImpl::MarkDirect(const tailgate::crypto::Bytes32& peer,
                                const tailgate::net::Endpoint& endpoint)
{
    const auto found = m_peers.find(peer);
    return found != m_peers.end() && found->second.Path.MarkDirect(endpoint);
}

bool ConnectionImpl::ExpireDirectPath(const tailgate::crypto::Bytes32& peer) noexcept
{
    const auto found = m_peers.find(peer);
    return found != m_peers.end() && found->second.Path.ExpireDirectPath(m_timeProvider.Now());
}

void ConnectionImpl::ResetPath(
    const tailgate::crypto::Bytes32& peer,
    tailgate::wgengine::magicsock::PeerPathState::ResetMode mode) noexcept
{
    const auto found = m_peers.find(peer);
    if (found != m_peers.end())
    {
        found->second.Path.Reset(mode);
    }
}

ConnectionImpl::EventResult ConnectionImpl::ProcessEvent(const tailgate::base::Event& event,
                                                         std::size_t maximumDatagrams,
                                                         std::size_t maximumDatagramSize)
{
    if (!m_socket || m_readinessToken.Value == 0 || event.Token != m_readinessToken)
    {
        return {};
    }
    EventResult result{
        .Handled = true,
        .Status = EventStatus::Ready,
        .Datagrams = {},
    };
    if (tailgate::base::HasReadiness(event.Readiness, tailgate::base::EventReadiness::Error))
    {
        result.Status = EventStatus::Error;
        return result;
    }
    if (tailgate::base::HasReadiness(event.Readiness, tailgate::base::EventReadiness::Closed))
    {
        result.Status = EventStatus::Closed;
        return result;
    }
    if (tailgate::base::HasReadiness(event.Readiness, tailgate::base::EventReadiness::Writable))
    {
        result.Status = FlushPending();
        if (result.Status != EventStatus::Ready)
        {
            return result;
        }
    }
    if (!tailgate::base::HasReadiness(event.Readiness, tailgate::base::EventReadiness::Readable))
    {
        return result;
    }
    for (std::size_t index = 0; index < maximumDatagrams; ++index)
    {
        tailgate::types::nettype::UdpReceiveResult received =
            m_socket->TryReceive(maximumDatagramSize);
        if (received.Result == tailgate::types::nettype::SocketIoResult::WouldBlock)
        {
            break;
        }
        if (received.Result == tailgate::types::nettype::SocketIoResult::Closed)
        {
            result.Status = EventStatus::Closed;
            break;
        }
        result.Datagrams.push_back(std::move(received.Datagram));
    }
    return result;
}

std::size_t ConnectionImpl::QueuedPackets(const tailgate::crypto::Bytes32& peer) const noexcept
{
    const auto found = m_peers.find(peer);
    return found == m_peers.end() ? 0 : found->second.Pending.size();
}

std::size_t ConnectionImpl::QueuedBytes(const tailgate::crypto::Bytes32& peer) const noexcept
{
    const auto found = m_peers.find(peer);
    return found == m_peers.end() ? 0 : found->second.PendingBytes;
}

void ConnectionImpl::Close() noexcept
{
    m_peers.clear();
    if (m_socket)
    {
        m_socket->Close();
        m_socket.reset();
    }
    m_readinessToken = {};
}

bool ConnectionImpl::Queue(PeerState& peer,
                           const tailgate::net::Endpoint& destination,
                           const std::vector<std::uint8_t>& payload)
{
    while (!peer.Pending.empty() &&
           (peer.Pending.size() >= MaximumPendingPacketsPerPeer ||
            peer.PendingBytes + payload.size() > MaximumPendingBytesPerPeer))
    {
        peer.PendingBytes -= peer.Pending.front().Payload.size();
        peer.Pending.pop_front();
        m_logger.LogWarning("outgoing UDP queue limit reached; dropping oldest datagram");
    }
    if (payload.size() > MaximumPendingBytesPerPeer)
    {
        m_logger.LogWarning("outgoing UDP datagram exceeds queue byte limit; dropping datagram");
        return false;
    }
    peer.PendingBytes += payload.size();
    peer.Pending.push_back(PeerState::PendingDatagram{
        .Destination = destination,
        .Payload = payload,
    });
    UpdateWriteInterest();
    return true;
}

tailgate::types::nettype::SocketIoResult ConnectionImpl::FlushPeer(PeerState& peer)
{
    while (!peer.Pending.empty())
    {
        const PeerState::PendingDatagram& pending = peer.Pending.front();
        const tailgate::types::nettype::SocketIoResult sent =
            m_socket->TrySendTo(pending.Destination, pending.Payload);
        if (sent == tailgate::types::nettype::SocketIoResult::Unavailable)
        {
            peer.PendingBytes -= pending.Payload.size();
            peer.Pending.pop_front();
            m_logger.LogWarning("outgoing UDP path unavailable; dropping queued datagram");
            continue;
        }
        if (sent != tailgate::types::nettype::SocketIoResult::Complete)
        {
            return sent;
        }
        peer.PendingBytes -= pending.Payload.size();
        peer.Pending.pop_front();
    }
    return tailgate::types::nettype::SocketIoResult::Complete;
}

ConnectionImpl::EventStatus ConnectionImpl::FlushPending()
{
    for (auto& [_, peer] : m_peers)
    {
        if (peer.Pending.empty())
        {
            continue;
        }
        const tailgate::types::nettype::SocketIoResult flushed = FlushPeer(peer);
        if (flushed == tailgate::types::nettype::SocketIoResult::Closed)
        {
            return EventStatus::Closed;
        }
        if (flushed == tailgate::types::nettype::SocketIoResult::WouldBlock)
        {
            UpdateWriteInterest();
            return EventStatus::Ready;
        }
    }
    UpdateWriteInterest();
    return EventStatus::Ready;
}

void ConnectionImpl::UpdateWriteInterest()
{
    if (!m_socket)
    {
        return;
    }
    const bool pending = std::any_of(m_peers.begin(),
                                     m_peers.end(),
                                     [](const auto& peer)
                                     {
                                         return !peer.second.Pending.empty();
                                     });
    m_socket->SetWriteInterest(pending);
}

} // namespace tailgate::wgengine::magicsock::impl
