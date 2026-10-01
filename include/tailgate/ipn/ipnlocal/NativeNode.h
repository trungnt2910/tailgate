#pragma once

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/control/client/RetryBackoff.h>
#include <tailgate/ipn/ipnlocal/DerpConnections.h>
#include <tailgate/ipn/ipnlocal/NetworkPolicy.h>
#include <tailgate/ipn/ipnlocal/NodeBackend.h>

namespace tailgate::ipn::ipnlocal
{

// A native backend with replaceable network sockets. The injected protocol owner and local services
// may outlive this object, so retiring a path does not destroy WireGuard or service state. All
// methods run on the serialized node worker, never a host packet callback.
class NativeNode final : public NodeBackend
{
public:
    NativeNode(wgengine::Session& session,
               wgengine::Engine& engine,
               wgengine::magicsock::Connection& udp,
               LocalServices& services,
               DnsForwarder& dns,
               wgengine::ping::Tracker& pings,
               base::TimeProvider& time,
               DerpTransportFactory& derps);

    void Start(types::netmap::NetworkConfig network,
               wgengine::SessionOptions options,
               const wgengine::tstun::DeviceOptions& device,
               types::nettype::UdpSocketOptions udp,
               std::optional<net::Endpoint> stunServer = std::nullopt,
               bool enableDerp = true);
    void UpdateNetwork(types::netmap::NetworkConfig network) override;
    void SetPeerApiPort(std::optional<std::uint16_t> port) noexcept override;
    [[nodiscard]] DnsForward ForwardDns(const net::Endpoint& client,
                                        std::vector<std::uint8_t> payload,
                                        const std::vector<std::string>& fallbackResolvers) override;
    [[nodiscard]] std::optional<DnsReply> CompleteDns(const net::Endpoint& source,
                                                      std::vector<std::uint8_t> payload) override;
    void PublishEndpoints(const net::Endpoint& local,
                          std::optional<net::Endpoint> publicEndpoint) override;
    [[nodiscard]] const NetworkPolicy& Policy() const noexcept override;
    [[nodiscard]] bool Connected() const;
    [[nodiscard]] bool OwnershipReady() const;
    void UpdateStatus(Status& status) const override;
    void Shutdown() override;
    [[nodiscard]] bool Ready() const noexcept override;
    [[nodiscard]] wgengine::ping::StartStatus
    StartPing(const wgengine::ping::Request& request) override;
    void Poll(std::size_t maximumPackets);
    void ChangeNetwork(std::string networkInterface, std::optional<net::Endpoint> stunServer);
    void SetStunServer(std::optional<net::Endpoint> stunServer);
    void SetDerpEnabled(bool enabled);
    void SuspendNetwork();
    void PrepareTransport();
    void PollTransport();
    void Select();
    [[nodiscard]] bool TransportPrepared() const;
    [[nodiscard]] std::optional<NativeEndpoints> TakeEndpoints();
    [[nodiscard]] NodeEvents Wait(std::size_t maximumEvents,
                                  std::size_t maximumPackets,
                                  std::size_t maximumPacketSize) override;
    [[nodiscard]] const types::netmap::NetworkConfig& Network() const noexcept override;

private:
    [[nodiscard]] PacketDelivery Delivery();
    void ScheduleUdpRebind();
    void PollUdpRebind();

    wgengine::Session& m_session;
    wgengine::Engine& m_engine;
    wgengine::magicsock::Connection& m_udp;
    base::TimeProvider& m_time;
    DnsForwarder& m_dns;
    wgengine::ping::Tracker& m_pings;
    NodeRuntime m_runtime;
    DerpConnections m_derps;
    NetworkPolicy m_policy{""};
    std::size_t m_homeDerp = 0;
    types::netmap::NetworkConfig m_network;
    std::string m_exitNode;
    types::nettype::UdpSocketOptions m_udpOptions;
    std::optional<base::TimeProvider::TimePoint> m_nextUdpBind;
    std::optional<NativeEndpoints> m_endpoints;
    std::optional<net::Endpoint> m_stunServer;
    static constexpr auto StunTimeout = std::chrono::seconds(3);
    static constexpr auto MinimumRebindDelay = std::chrono::seconds(1);
    static constexpr auto MaximumRebindDelay = std::chrono::seconds(30);
    static constexpr auto BindTimeout = std::chrono::seconds(10);
    control::client::RetryBackoff m_rebindBackoff{MinimumRebindDelay, MaximumRebindDelay};
    bool m_udpBinding = false;
    bool m_started = false;
    bool m_derpEnabled = true;
};

} // namespace tailgate::ipn::ipnlocal
