#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/base/EventLoop.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/net/Endpoint.h>
#include <tailgate/types/nettype/UdpSocket.h>
#include <tailgate/wgengine/magicsock/PeerPathState.h>

namespace tailgate::wgengine::magicsock
{

class Connection
{
public:
    enum class EventStatus
    {
        Ready,
        Closed,
        Error,
    };

    struct EventResult
    {
        bool Handled = false;
        EventStatus Status = EventStatus::Ready;
        std::vector<tailgate::types::nettype::UdpDatagram> Datagrams;
    };

    enum class DirectSendResult
    {
        Sent,
        Queued,
        Dropped,
        Unavailable,
    };

    virtual ~Connection();

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    [[nodiscard]] virtual bool Open(const tailgate::types::nettype::UdpSocketOptions& options) = 0;
    [[nodiscard]] virtual bool AddPeer(const tailgate::crypto::Bytes32& peer) = 0;
    [[nodiscard]] virtual bool RemovePeer(const tailgate::crypto::Bytes32& peer) = 0;
    [[nodiscard]] virtual bool HasPeer(const tailgate::crypto::Bytes32& peer) const noexcept = 0;
    [[nodiscard]] virtual std::optional<tailgate::net::Endpoint> LocalEndpoint() const = 0;

    [[nodiscard]] virtual std::optional<tailgate::types::nettype::SocketIoResult>
    TrySendProbe(const tailgate::net::Endpoint& destination,
                 const std::vector<std::uint8_t>& payload) = 0;
    [[nodiscard]] virtual std::optional<tailgate::types::nettype::SocketIoResult>
    TrySendDirect(const tailgate::crypto::Bytes32& peer,
                  const tailgate::net::Endpoint& destination,
                  const std::vector<std::uint8_t>& payload) = 0;
    [[nodiscard]] virtual DirectSendResult SendDirect(const tailgate::crypto::Bytes32& peer,
                                                      const tailgate::net::Endpoint& destination,
                                                      const std::vector<std::uint8_t>& payload) = 0;
    [[nodiscard]] virtual DirectSendResult Send(const tailgate::crypto::Bytes32& peer,
                                                const std::vector<std::uint8_t>& payload,
                                                bool expectResponse = true) = 0;
    [[nodiscard]] virtual bool
    HasDirectPath(const tailgate::crypto::Bytes32& peer) const noexcept = 0;
    [[nodiscard]] virtual std::optional<tailgate::net::Endpoint>
    DirectEndpoint(const tailgate::crypto::Bytes32& peer) const noexcept = 0;
    [[nodiscard]] virtual std::optional<tailgate::crypto::Bytes32>
    AcceptDirectSource(const tailgate::net::Endpoint& endpoint) noexcept = 0;
    [[nodiscard]] virtual bool TryBeginProbe(const tailgate::crypto::Bytes32& peer) noexcept = 0;
    [[nodiscard]] virtual bool MarkDirect(const tailgate::crypto::Bytes32& peer,
                                          const tailgate::net::Endpoint& endpoint) = 0;
    [[nodiscard]] virtual bool ExpireDirectPath(const tailgate::crypto::Bytes32& peer) noexcept = 0;
    virtual void
    ResetPath(const tailgate::crypto::Bytes32& peer,
              tailgate::wgengine::magicsock::PeerPathState::ResetMode mode) noexcept = 0;
    [[nodiscard]] virtual EventResult ProcessEvent(const tailgate::base::Event& event,
                                                   std::size_t maximumDatagrams,
                                                   std::size_t maximumDatagramSize) = 0;
    [[nodiscard]] virtual std::size_t
    QueuedPackets(const tailgate::crypto::Bytes32& peer) const noexcept = 0;
    [[nodiscard]] virtual std::size_t
    QueuedBytes(const tailgate::crypto::Bytes32& peer) const noexcept = 0;

    virtual void Close() noexcept = 0;

protected:
    Connection() = default;
};

} // namespace tailgate::wgengine::magicsock
