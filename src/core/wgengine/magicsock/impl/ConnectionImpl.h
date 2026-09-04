#pragma once

#include <cstddef>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <vector>

#include <tailgate/base/EventLoop.h>
#include <tailgate/base/Logger.h>
#include <tailgate/base/TimeProvider.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/net/Endpoint.h>
#include <tailgate/types/nettype/UdpSocket.h>
#include <tailgate/wgengine/magicsock/Connection.h>

namespace tailgate::wgengine::magicsock::impl
{

class ConnectionImpl final : public tailgate::wgengine::magicsock::Connection
{
public:
    ConnectionImpl(tailgate::types::nettype::UdpSocketFactory& socketFactory,
                   tailgate::base::TimeProvider& timeProvider) noexcept;
    ~ConnectionImpl() override;

    [[nodiscard]] bool Open(const tailgate::types::nettype::UdpSocketOptions& options) override;
    [[nodiscard]] bool AddPeer(const tailgate::crypto::Bytes32& peer) override;
    [[nodiscard]] bool RemovePeer(const tailgate::crypto::Bytes32& peer) override;
    [[nodiscard]] bool HasPeer(const tailgate::crypto::Bytes32& peer) const noexcept override;
    [[nodiscard]] std::optional<tailgate::net::Endpoint> LocalEndpoint() const override;

    [[nodiscard]] std::optional<tailgate::types::nettype::SocketIoResult>
    TrySendProbe(const tailgate::net::Endpoint& destination,
                 const std::vector<std::uint8_t>& payload) override;
    void ProbePeer(const tailgate::crypto::Bytes32& peer,
                   const std::vector<std::uint8_t>& payload) override;
    [[nodiscard]] std::optional<tailgate::types::nettype::SocketIoResult>
    TrySendDirect(const tailgate::crypto::Bytes32& peer,
                  const tailgate::net::Endpoint& destination,
                  const std::vector<std::uint8_t>& payload) override;
    [[nodiscard]] DirectSendResult SendDirect(const tailgate::crypto::Bytes32& peer,
                                              const tailgate::net::Endpoint& destination,
                                              const std::vector<std::uint8_t>& payload) override;
    [[nodiscard]] DirectSendResult Send(const tailgate::crypto::Bytes32& peer,
                                        const std::vector<std::uint8_t>& payload,
                                        bool expectResponse) override;
    [[nodiscard]] bool HasDirectPath(const tailgate::crypto::Bytes32& peer) const noexcept override;
    [[nodiscard]] std::optional<tailgate::net::Endpoint>
    DirectEndpoint(const tailgate::crypto::Bytes32& peer) const noexcept override;
    [[nodiscard]] std::optional<tailgate::crypto::Bytes32>
    AcceptDirectSource(const tailgate::net::Endpoint& endpoint) noexcept override;
    [[nodiscard]] bool TryBeginProbe(const tailgate::crypto::Bytes32& peer) noexcept override;
    [[nodiscard]] bool MarkDirect(const tailgate::crypto::Bytes32& peer,
                                  const tailgate::net::Endpoint& endpoint) override;
    [[nodiscard]] bool ExpireDirectPath(const tailgate::crypto::Bytes32& peer) noexcept override;
    void ResetPath(const tailgate::crypto::Bytes32& peer,
                   tailgate::wgengine::magicsock::PeerPathState::ResetMode mode) noexcept override;
    [[nodiscard]] EventResult ProcessEvent(const tailgate::base::Event& event,
                                           std::size_t maximumDatagrams,
                                           std::size_t maximumDatagramSize) override;
    [[nodiscard]] std::size_t
    QueuedPackets(const tailgate::crypto::Bytes32& peer) const noexcept override;
    [[nodiscard]] std::size_t
    QueuedBytes(const tailgate::crypto::Bytes32& peer) const noexcept override;

    void Close() noexcept override;

private:
    struct PeerState
    {
        struct PendingDatagram
        {
            tailgate::net::Endpoint Destination;
            std::vector<std::uint8_t> Payload;
        };

        std::deque<PendingDatagram> Pending;
        tailgate::wgengine::magicsock::PeerPathState Path;
        std::size_t PendingBytes = 0;
    };

    [[nodiscard]] bool Queue(PeerState& peer,
                             const tailgate::net::Endpoint& destination,
                             const std::vector<std::uint8_t>& payload);
    [[nodiscard]] tailgate::types::nettype::SocketIoResult FlushPeer(PeerState& peer);
    [[nodiscard]] EventStatus FlushPending();
    void UpdateWriteInterest();

    static constexpr std::size_t MaximumPendingPacketsPerPeer = 1024;
    static constexpr std::size_t MaximumPendingBytesPerPeer = 4U * 1024U * 1024U;

    tailgate::types::nettype::UdpSocketFactory& m_socketFactory;
    tailgate::base::TimeProvider& m_timeProvider;
    std::unique_ptr<tailgate::types::nettype::UdpSocket> m_socket;
    tailgate::base::EventToken m_readinessToken;
    std::map<tailgate::crypto::Bytes32, PeerState> m_peers;
    tailgate::base::Logger m_logger{"magicsock"};
};

} // namespace tailgate::wgengine::magicsock::impl
