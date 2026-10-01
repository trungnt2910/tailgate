#pragma once

#include <tailgate/ipn/ipnlocal/HostedNode.h>
#include <tailgate/ipn/ipnlocal/NativeNode.h>
#include <tailgate/ipn/ipnlocal/TransitionCoordinator.h>

namespace tailgate::ipn::ipnlocal
{

// Composes two paths around one session/device/protocol/service scope. Hosts supply
// sockets and bootstrap options; transition ordering and rollback remain in Core.
class SwitchingNode final : public NodeBackend
{
public:
    SwitchingNode(NativeNode& native,
                  HostedNode& hosted,
                  hosted::Recovery& preparation,
                  base::TimeProvider& time,
                  NodeMode initial,
                  wgengine::tstun::DeviceOptions device,
                  std::string exitNode);
    [[nodiscard]] bool RequestMode(NodeMode desired,
                                   std::optional<hosted::ConnectionOptions> relay = std::nullopt);
    void CancelTransition(TransitionFailure reason = TransitionFailure::Cancelled);
    void ChangeNetwork(std::optional<std::string> networkInterface);
    void SetStunServer(std::optional<net::Endpoint> server);
    [[nodiscard]] bool TransportReady() const;
    [[nodiscard]] const TransitionStatus& Transition() const noexcept;
    void UpdateNetwork(types::netmap::NetworkConfig network) override;
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
    void SetPeerApiPort(std::optional<std::uint16_t> port) noexcept override;
    void UpdateStatus(Status& status) const override;
    void PublishEndpoints(const net::Endpoint& local,
                          std::optional<net::Endpoint> publicEndpoint) override;
    [[nodiscard]] bool Ready() const noexcept override;
    void Shutdown() override;

private:
    [[nodiscard]] NodeBackend& Active() const noexcept;
    void Advance(std::size_t maximumPackets, NodeEvents& result);
    void ApplyActions();
    void Observe(const NodeEvents& result);
    void ReconcileMap();
    [[nodiscard]] std::vector<std::uint16_t> Regions() const;
    static void Merge(NodeEvents& destination, NodeEvents source);
    NativeNode& m_native;
    HostedNode& m_hosted;
    hosted::Recovery& m_preparation;
    TransitionCoordinator m_transition;
    NodeMode m_selected;
    wgengine::tstun::DeviceOptions m_device;
    std::string m_exitNode;
    std::string m_relayName;
    std::optional<hosted::ConnectionOptions> m_relayOptions;
    std::optional<hosted::ConnectionResult> m_preparedRelay;
    std::uint64_t m_appliedMap = 0;
    std::uint64_t m_preparationGeneration = 0;
};

} // namespace tailgate::ipn::ipnlocal
