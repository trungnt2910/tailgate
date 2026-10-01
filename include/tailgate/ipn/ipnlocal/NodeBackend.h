#pragma once

#include <system_error>

#include <tailgate/Status.h>
#include <tailgate/hosted/Delegation.h>
#include <tailgate/ipn/ipnlocal/NodeRuntime.h>
#include <tailgate/wgengine/Session.h>

namespace tailgate::ipn::ipnlocal
{

struct NativeEndpoints
{
    net::Endpoint BoundEndpoint;
    std::optional<net::Endpoint> PublicEndpoint;
};

struct NodeEvents
{
    wgengine::SessionWaitResult Transport;
    std::vector<NodeReceiveResult> Received;
    std::optional<NativeEndpoints> Endpoints;
    std::optional<std::error_code> TransportFailure;
    std::vector<hosted::DelegationReply> DelegationReplies;
    std::optional<std::uint64_t> AppliedMapRevision;
    bool NetworkChanged = false;
    bool DataPathReady = false;
};

// Portable node operations used by host adapters. A backend owns delivery through one
// transport policy; the injected PeerProtocol, DNS/ping and LocalServices belong to the node.
class NodeBackend
{
public:
    virtual ~NodeBackend() = default;
    virtual void UpdateNetwork(types::netmap::NetworkConfig network) = 0;
    [[nodiscard]] virtual NodeEvents
    Wait(std::size_t maximumEvents, std::size_t maximumPackets, std::size_t maximumPacketSize) = 0;
    [[nodiscard]] virtual wgengine::ping::StartStatus
    StartPing(const wgengine::ping::Request& request) = 0;
    [[nodiscard]] virtual DnsForward
    ForwardDns(const net::Endpoint& client,
               std::vector<std::uint8_t> payload,
               const std::vector<std::string>& fallbackResolvers) = 0;
    [[nodiscard]] virtual std::optional<DnsReply>
    CompleteDns(const net::Endpoint& source, std::vector<std::uint8_t> payload) = 0;
    [[nodiscard]] virtual const types::netmap::NetworkConfig& Network() const noexcept = 0;
    [[nodiscard]] virtual const NetworkPolicy& Policy() const noexcept = 0;
    virtual void SetPeerApiPort(std::optional<std::uint16_t> port) noexcept = 0;
    virtual void UpdateStatus(Status& status) const = 0;
    virtual void PublishEndpoints(const net::Endpoint& local,
                                  std::optional<net::Endpoint> publicEndpoint) = 0;
    [[nodiscard]] virtual bool Ready() const noexcept = 0;
    virtual void Shutdown() = 0;
};

} // namespace tailgate::ipn::ipnlocal
