#pragma once

#include <chrono>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/base/TimeProvider.h>
#include <tailgate/crypto/Random.h>
#include <tailgate/net/stun/Stun.h>
#include <tailgate/wgengine/Engine.h>
#include <tailgate/wgengine/PeerProtocol.h>
#include <tailgate/wgengine/Session.h>
#include <tailgate/wgengine/magicsock/Connection.h>
#include <tailgate/wgengine/wireguard/Router.h>

namespace tailgate::wgengine::impl
{

class SessionImpl final : public tailgate::wgengine::Session
{
public:
    SessionImpl(tailgate::wgengine::Engine& engine,
                tailgate::base::TimeProvider& timeProvider,
                tailgate::crypto::Random& random,
                tailgate::wgengine::magicsock::Connection& connection,
                PeerProtocol& protocol) noexcept;

    void Reset() noexcept override;

    void SetControlConnection(
        std::unique_ptr<tailgate::control::client::Connection> connection) override;
    [[nodiscard]] tailgate::control::client::Connection* ControlConnection() noexcept override;
    [[nodiscard]] tailgate::wgengine::DerpConnectionId
    AddDerpConnection(int region, std::unique_ptr<tailgate::derp::Connection> connection) override;
    [[nodiscard]] tailgate::derp::Connection&
    DerpConnection(tailgate::wgengine::DerpConnectionId connection) override;
    [[nodiscard]] std::size_t DerpConnectionCount() const noexcept override;
    [[nodiscard]] std::optional<tailgate::net::Endpoint>
    DiscoverEndpoint(const tailgate::net::Endpoint& server,
                     std::chrono::milliseconds timeout) override;
    void StartEndpointDiscovery(const tailgate::net::Endpoint& server,
                                std::chrono::milliseconds timeout) override;
    void CancelEndpointDiscovery() noexcept override;
    void Configure(tailgate::wgengine::SessionOptions options) override;
    void SetAdvertisedEndpoint(const tailgate::net::Endpoint& endpoint) override;
    void UpdatePeers(const std::vector<tailgate::types::netmap::PeerConfig>& peers,
                     std::string exitNode) override;
    void SendPacket(const std::vector<std::uint8_t>& plaintext) override;
    void SendPacketTo(const tailgate::crypto::Bytes32& peer,
                      const std::vector<std::uint8_t>& plaintext) override;
    void StartPeer(const tailgate::crypto::Bytes32& peer) override;
    [[nodiscard]] std::optional<tailgate::disco::Disco::TransactionId>
    SendDiscoPing(const tailgate::crypto::Bytes32& peer) override;
    [[nodiscard]] bool CanDisco(const tailgate::crypto::Bytes32& peer) const noexcept override;
    [[nodiscard]] std::optional<tailgate::wgengine::SessionPeerStats>
    PeerStats(const tailgate::crypto::Bytes32& peer) const noexcept override;
    [[nodiscard]] tailgate::wgengine::SessionWaitResult
    Wait(std::size_t maximumEvents,
         std::size_t maximumPacketsPerSource,
         std::size_t maximumPacketSize,
         std::optional<base::TimeProvider::TimePoint> deadline = std::nullopt) override;
    void Wake() noexcept override;
    void SetPacketPath(std::optional<std::reference_wrapper<PacketPath>> path) override;

private:
    struct Discovery
    {
        net::stun::TransactionId Transaction;
        net::Endpoint Server;
        base::TimeProvider::TimePoint Deadline;
        base::TimeProvider::TimePoint NextSend;
        std::chrono::milliseconds RetryDelay;
    };

    void PollEndpointDiscovery(SessionWaitResult& result);
    [[nodiscard]] bool ProcessEndpointResponse(const types::nettype::UdpDatagram& datagram,
                                               SessionWaitResult& result);

    struct DerpState
    {
        int Region = 0;
        std::unique_ptr<tailgate::derp::Connection> Connection;
    };

    struct PeerState
    {
        tailgate::types::netmap::PeerConfig Config;
        tailgate::crypto::Bytes32 PublicKey{};
        std::optional<tailgate::crypto::Bytes32> DiscoKey;
        std::vector<tailgate::net::Endpoint> Endpoints;
        std::uint64_t TransmittedBytes = 0;
        std::uint64_t ReceivedBytes = 0;
        bool Active = true;
    };

    [[nodiscard]] PeerState* FindPeer(const tailgate::crypto::Bytes32& peer) noexcept;
    [[nodiscard]] const PeerState* FindPeer(const tailgate::crypto::Bytes32& peer) const noexcept;
    [[nodiscard]] PeerState* FindDiscoPeer(const tailgate::crypto::Bytes32& discoKey) noexcept;
    [[nodiscard]] DerpState* FindDerp(int region) noexcept;
    void
    Dispatch(std::vector<tailgate::wgengine::wireguard::WireGuardRouter::TransportPacket> packets);
    void SendTransport(PeerState& peer,
                       const std::vector<std::uint8_t>& payload,
                       bool expectResponse,
                       tailgate::derp::DerpSendQueue::Priority priority);
    void SendRelay(PeerState& peer,
                   const std::vector<std::uint8_t>& payload,
                   tailgate::derp::DerpSendQueue::Priority priority);
    void StartDirectProbe(PeerState& peer);
    [[nodiscard]] bool
    ProcessDiscoPacket(const tailgate::crypto::Bytes32* derpSource,
                       const std::optional<tailgate::net::Endpoint>& directSource,
                       std::optional<tailgate::wgengine::DerpConnectionId> derpConnection,
                       const std::vector<std::uint8_t>& packet,
                       tailgate::wgengine::SessionWaitResult& result);
    void MarkDirect(PeerState& peer,
                    const tailgate::net::Endpoint& endpoint,
                    tailgate::wgengine::SessionWaitResult& result);
    void ProcessProtocolEvents(tailgate::wgengine::EngineWaitResult engineResult,
                               tailgate::wgengine::SessionWaitResult& result);
    [[nodiscard]] bool
    ProcessWireGuardPacket(const tailgate::crypto::Bytes32* source,
                           const std::optional<tailgate::net::Endpoint>& directSource,
                           std::optional<tailgate::wgengine::DerpConnectionId> derpConnection,
                           const std::vector<std::uint8_t>& packet,
                           tailgate::wgengine::SessionWaitResult& result);
    void MaintainConnections(tailgate::wgengine::SessionWaitResult& result);
    void Maintain(tailgate::wgengine::SessionWaitResult& result);

    static constexpr std::chrono::seconds MaintenanceInterval{1};
    static constexpr auto InitialStunRetryDelay = std::chrono::milliseconds(500);
    static constexpr std::size_t StunMaximumEvents = 1;
    static constexpr std::size_t StunMaximumDatagrams = 16;
    static constexpr std::size_t StunMaximumDatagramSize = 4096;

    tailgate::wgengine::Engine& m_engine;
    tailgate::base::TimeProvider& m_timeProvider;
    tailgate::crypto::Random& m_random;
    tailgate::wgengine::magicsock::Connection& m_connection;
    std::unique_ptr<tailgate::control::client::Connection> m_control;
    std::vector<DerpState> m_derps;
    std::deque<PeerState> m_peers;
    PeerProtocol& m_protocol;
    std::optional<std::reference_wrapper<PacketPath>> m_packetPath;
    std::optional<Discovery> m_discovery;
    bool m_configured = false;
    tailgate::net::Endpoint m_advertisedEndpoint;
    int m_homeDerpRegion = 0;
    tailgate::base::TimeProvider::TimePoint m_nextMaintenance;
};

} // namespace tailgate::wgengine::impl
