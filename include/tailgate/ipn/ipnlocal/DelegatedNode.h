#pragma once

#include <tailgate/hosted/Protocol.h>
#include <tailgate/ipn/ipnlocal/DelegationLease.h>
#include <tailgate/ipn/ipnlocal/DerpConnections.h>
#include <tailgate/ipn/ipnlocal/PeerTable.h>

namespace tailgate::ipn::ipnlocal
{

// Relays encrypted packets for a hosted client. Only that client owns WireGuard/disco keys;
// this node forwards source metadata and accepts endpoint proofs from its authenticated link.
class DelegatedNode final
{
public:
    DelegatedNode(wgengine::Session& session,
                  wgengine::Engine& engine,
                  wgengine::magicsock::Connection& udp,
                  DerpTransportFactory& derps,
                  base::TimeProvider& time);
    void Start(const types::netmap::NetworkConfig& network,
               const wgengine::tstun::DeviceOptions& device);
    void HandleControl(const std::vector<std::uint8_t>& bytes);
    [[nodiscard]] std::vector<hosted::Frame> TakeControlOutput();
    [[nodiscard]] wgengine::SessionWaitResult
    Wait(std::size_t maximumEvents, std::size_t maximumPackets, std::size_t maximumPacketSize);
    [[nodiscard]] bool Connected() const;

private:
    void UpdateNetwork(const types::netmap::NetworkConfig& network);
    void HandleOutbound(const hosted::PeerPacket& packet);
    void Deliver(const crypto::Bytes32& peer,
                 const std::vector<std::uint8_t>& payload,
                 bool disco,
                 const std::optional<net::Endpoint>& source,
                 std::optional<hosted::DerpRoute> route);
    wgengine::Session& m_session;
    wgengine::Engine& m_engine;
    wgengine::magicsock::Connection& m_udp;
    DerpConnections m_derps;
    DelegationLease m_delegation;
    std::uint64_t m_mapRevision = 0;
    std::vector<hosted::Frame> m_controlOutput;
    PeerTable m_peers;
    std::size_t m_homeDerp = 0;
    bool m_started = false;
};

} // namespace tailgate::ipn::ipnlocal
