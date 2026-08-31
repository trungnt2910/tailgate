#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/base/EventLoop.h>
#include <tailgate/control/client/Connection.h>
#include <tailgate/derp/Connection.h>
#include <tailgate/disco/Disco.h>
#include <tailgate/net/Endpoint.h>
#include <tailgate/types/netmap/NetworkMap.h>
#include <tailgate/types/nettype/UdpSocket.h>
#include <tailgate/wgengine/Engine.h>

namespace tailgate::wgengine
{

using DerpConnectionId = std::size_t;

struct SessionDerpPacket
{
    DerpConnectionId Connection = 0;
    tailgate::derp::DerpClient::Packet Packet;
};

struct SessionWireGuardEvent
{
    tailgate::crypto::Bytes32 Peer{};
    std::vector<std::vector<std::uint8_t>> Plaintext;
    std::optional<tailgate::net::Endpoint> DirectSource;
    std::size_t TransportBytes = 0;
    bool SessionEstablished = false;
};

struct SessionDiscoEvent
{
    tailgate::crypto::Bytes32 Peer{};
    tailgate::disco::Disco::MessageType Type = tailgate::disco::Disco::MessageType::Ping;
    tailgate::disco::Disco::TransactionId Transaction{};
    std::optional<tailgate::net::Endpoint> DirectSource;
};

struct SessionPathEvent
{
    tailgate::crypto::Bytes32 Peer{};
    std::optional<tailgate::net::Endpoint> DirectEndpoint;
};

struct SessionOptions
{
    tailgate::crypto::Bytes32 NodePrivateKey{};
    tailgate::crypto::Bytes32 NodePublicKey{};
    tailgate::crypto::Bytes32 DiscoPrivateKey{};
    tailgate::net::Endpoint AdvertisedEndpoint{};
    int HomeDerpRegion = 0;
    std::vector<tailgate::types::netmap::PeerConfig> Peers;
    std::string ExitNode;
};

struct SessionPeerStats
{
    std::uint64_t TransmittedBytes = 0;
    std::uint64_t ReceivedBytes = 0;
    bool WireGuardSession = false;
    std::optional<tailgate::net::Endpoint> DirectEndpoint;
};

struct SessionWaitResult
{
    tailgate::base::EventWaitStatus Status = tailgate::base::EventWaitStatus::Events;
    std::vector<tailgate::types::nettype::UdpDatagram> Datagrams;
    std::vector<std::vector<std::uint8_t>> Packets;
    std::vector<tailgate::wgengine::EngineEventFailure> Failures;
    std::vector<tailgate::types::netmap::NetworkConfig> NetworkMaps;
    std::vector<SessionDerpPacket> DerpPackets;
    std::vector<SessionWireGuardEvent> WireGuardEvents;
    std::vector<SessionDiscoEvent> DiscoEvents;
    std::vector<SessionPathEvent> PathEvents;
    std::vector<tailgate::base::Event> PlatformEvents;
    bool MaintenanceDue = false;
};

class Session
{
public:
    virtual ~Session();

    virtual void
    SetControlConnection(std::unique_ptr<tailgate::control::client::Connection> connection) = 0;
    [[nodiscard]] virtual tailgate::control::client::Connection* ControlConnection() noexcept = 0;
    [[nodiscard]] virtual DerpConnectionId
    AddDerpConnection(int region, std::unique_ptr<tailgate::derp::Connection> connection) = 0;
    [[nodiscard]] virtual tailgate::derp::Connection&
    DerpConnection(DerpConnectionId connection) = 0;
    [[nodiscard]] virtual std::size_t DerpConnectionCount() const noexcept = 0;
    [[nodiscard]] virtual std::optional<tailgate::net::Endpoint>
    DiscoverEndpoint(const tailgate::net::Endpoint& server, std::chrono::milliseconds timeout) = 0;
    virtual void Configure(SessionOptions options) = 0;
    virtual void UpdatePeers(const std::vector<tailgate::types::netmap::PeerConfig>& peers,
                             std::string exitNode = {}) = 0;
    virtual void SendPacket(const std::vector<std::uint8_t>& plaintext) = 0;
    virtual void SendPacketTo(const tailgate::crypto::Bytes32& peer,
                              const std::vector<std::uint8_t>& plaintext) = 0;
    virtual void StartPeer(const tailgate::crypto::Bytes32& peer) = 0;
    [[nodiscard]] virtual std::optional<tailgate::disco::Disco::TransactionId>
    SendDiscoPing(const tailgate::crypto::Bytes32& peer) = 0;
    [[nodiscard]] virtual bool CanDisco(const tailgate::crypto::Bytes32& peer) const noexcept = 0;
    [[nodiscard]] virtual std::optional<SessionPeerStats>
    PeerStats(const tailgate::crypto::Bytes32& peer) const noexcept = 0;
    [[nodiscard]] virtual SessionWaitResult Wait(std::size_t maximumEvents,
                                                 std::size_t maximumPacketsPerSource,
                                                 std::size_t maximumPacketSize) = 0;
    virtual void Wake() noexcept = 0;

protected:
    Session() = default;
};

} // namespace tailgate::wgengine
