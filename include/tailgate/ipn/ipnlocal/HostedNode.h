#pragma once

#include <memory>

#include <tailgate/hosted/Connection.h>
#include <tailgate/hosted/Dns.h>
#include <tailgate/hosted/Recovery.h>
#include <tailgate/hosted/StreamTransport.h>
#include <tailgate/ipn/ipnlocal/NodeBackend.h>
#include <tailgate/wgengine/Session.h>

namespace tailgate::ipn::ipnlocal
{

// Hosted delivery around the same protocol and local-service owners as NativeNode.
// Preparing/authenticating a relay happens before attaching its nonblocking stream here.
class HostedNode final : public NodeBackend, public wgengine::PacketPath
{
public:
    HostedNode(hosted::Client& client,
               wgengine::Session& session,
               wgengine::Engine& engine,
               LocalServices& services,
               DnsForwarder& dns,
               wgengine::ping::Tracker& pings,
               base::TimeProvider& time,
               hosted::Dns& hostedDns,
               hosted::Recovery& recovery);
    void Start(hosted::ConnectionResult connection,
               const wgengine::tstun::DeviceOptions& device,
               std::string exitNode,
               std::string relayName);
    void UpdateNetwork(types::netmap::NetworkConfig network) override;
    void ReplaceTransport(hosted::ConnectionResult connection);
    void RetireTransport() noexcept;
    void ChangeNetwork(std::string networkInterface);
    void Select();
    void Send(const wgengine::wireguard::WireGuardRouter::TransportPacket& packet) override;
    [[nodiscard]] NodeEvents PollTransport(std::size_t maximumPackets);
    [[nodiscard]] bool HasTransport() const noexcept;
    void StopRecovery();
    void ResumeRecovery();
    void RequestDelegation(const hosted::DelegationRequest& request);
    [[nodiscard]] std::uint64_t MapRevision() const noexcept;
    [[nodiscard]] NodeEvents Wait(std::size_t maximumEvents,
                                  std::size_t maximumPackets,
                                  std::size_t maximumPacketSize) override;
    [[nodiscard]] wgengine::ping::StartStatus
    StartPing(const wgengine::ping::Request& request) override;
    [[nodiscard]] DnsForward ForwardDns(const net::Endpoint& client,
                                        std::vector<std::uint8_t> payload,
                                        const std::vector<std::string>& fallbackResolvers) override;
    [[nodiscard]] std::optional<DnsReply> CompleteDns(const net::Endpoint& source,
                                                      std::vector<std::uint8_t> payload) override;
    [[nodiscard]] const types::netmap::NetworkConfig& Network() const noexcept override;
    [[nodiscard]] const NetworkPolicy& Policy() const noexcept override;
    void Shutdown() override;
    [[nodiscard]] bool Ready() const noexcept override;
    void SetPeerApiPort(std::optional<std::uint16_t> port) noexcept override;
    void UpdateStatus(Status& status) const override;
    void PublishEndpoints(const net::Endpoint& local,
                          std::optional<net::Endpoint> publicEndpoint) override;

private:
    [[nodiscard]] PacketDelivery Delivery();
    void Queue(std::vector<std::uint8_t> bytes);
    void Poll(NodeEvents& result, std::size_t maximumPackets, bool processLocal = true);
    void Receive(const hosted::Frame& frame, NodeEvents& result);
    void SendProbe(const wgengine::ping::Probe& packet);
    hosted::Client& m_client;
    wgengine::Session& m_session;
    wgengine::Engine& m_engine;
    DnsForwarder& m_dns;
    wgengine::ping::Tracker& m_pings;
    base::TimeProvider& m_time;
    hosted::Dns& m_hostedDns;
    hosted::Recovery& m_recovery;
    NodeRuntime m_runtime;
    NetworkPolicy m_policy{""};
    types::netmap::NetworkConfig m_network;
    std::string m_exitNode;
    std::string m_relayName;
    std::unique_ptr<hosted::StreamTransport> m_stream;
    bool m_ready = false;
    base::TimeProvider::TimePoint m_nextHeartbeat{};
    base::TimeProvider::TimePoint m_nextProbe{};
    base::TimeProvider::TimePoint m_nextMaintenance{};
};

} // namespace tailgate::ipn::ipnlocal
