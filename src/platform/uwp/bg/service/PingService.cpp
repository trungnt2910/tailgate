#include "PingService.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <vector>

#include <boost/algorithm/string/case_conv.hpp>

#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Ipv4.h>

#include "common/VpnConstants.h"

namespace tailgate::uwp::bg::service
{
namespace
{

constexpr std::chrono::seconds PingExpiry(10);

std::vector<std::uint8_t> BuildResponse(std::uint32_t appAddress,
                                        std::uint16_t appPort,
                                        app_service::Status status,
                                        std::uint64_t sequence,
                                        std::uint32_t latencyMicroseconds = 0,
                                        const std::string& relayName = {},
                                        const std::string& endpoint = {})
{
    const std::vector<std::uint8_t> payload =
        app_service::EncodePingResponse(app_service::PingResponse{
            .Result = status,
            .Sequence = sequence,
            .LatencyMicroseconds = latencyMicroseconds,
            .Direct = false,
            .Relay = relayName,
            .Endpoint = endpoint,
        });
    return tailgate::net::packet::Ipv4UdpDatagram::Build(VpnConstants::Network::ServiceIpv4Address,
                                                         appAddress,
                                                         VpnConstants::AppService::Port,
                                                         appPort,
                                                         payload);
}

} // namespace

PingService::PingService(manager::DataPlaneManager& dataPlaneManager,
                         tailgate::wgengine::ping::Tracker& tracker)
    : m_tracker(tracker)
{
    dataPlaneManager.Register(*this);
}

void PingService::Start(SessionGeneration)
{
}

void PingService::Stop()
{
    Reset();
}

void PingService::Reset()
{
    m_pending.clear();
    m_responses.clear();
    m_tracker.Reset();
    m_nextRequestId = 1;
}

void PingService::Encapsulate(EncapsulationContext& context)
{
    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> datagram =
        tailgate::net::packet::Ipv4UdpDatagram::Parse(context.Original);
    if (!datagram || datagram->Destination() != VpnConstants::Network::ServiceIpv4Address ||
        datagram->DestinationPort() != VpnConstants::AppService::Port)
    {
        return;
    }
    const std::optional<app_service::Message> message =
        app_service::DecodeMessage(datagram->Payload());
    if (!message || message->Type != app_service::MessageType::PingRequest)
    {
        return;
    }
    const std::optional<tailgate::net::Ipv4Address> self =
        tailgate::net::Ipv4Address::TryParse(context.Client.Network().SelfAddress());
    const std::optional<app_service::PingRequest> request =
        app_service::DecodePingRequest(*message);
    if (!self || datagram->Source() != self->HostOrder() || datagram->SourcePort() == 0 || !request)
    {
        m_logger.LogWarning("discarding invalid in-tunnel ping request");
        return;
    }
    Handle(*datagram,
           *request,
           context.Client.Network(),
           context.Client.Disco(),
           context.RelayName,
           context.RemoteOutput,
           m_responses);
}

void PingService::Decapsulate(DecapsulationContext&)
{
}

void PingService::FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput)
{
    for (std::vector<std::uint8_t>& response : m_responses)
    {
        localOutput.push_back(std::move(response));
    }
    m_responses.clear();
}

void PingService::Handle(const tailgate::net::packet::Ipv4UdpDatagram& datagram,
                         const app_service::PingRequest& request,
                         const tailgate::types::netmap::NetworkConfig& config,
                         tailgate::disco::Disco& disco,
                         const std::string& relayName,
                         std::vector<std::uint8_t>& relayOutput,
                         std::vector<std::vector<std::uint8_t>>& appResponses)
{
    const auto now = std::chrono::steady_clock::now();
    for (const tailgate::wgengine::ping::Result& expired : m_tracker.Expire(now))
    {
        std::erase_if(m_pending,
                      [&](const PendingResponse& pending)
                      {
                          return pending.RequestId == expired.RequestId;
                      });
        m_logger.LogDebug("app ping expired without a pong peer={}", expired.PeerName);
    }
    const auto respondError = [&](app_service::Status status)
    {
        appResponses.push_back(
            BuildResponse(datagram.Source(), datagram.SourcePort(), status, request.Sequence));
    };
    const std::uint64_t requestId = m_nextRequestId++;
    std::string selectedRelay = relayName;
    boost::algorithm::to_lower(selectedRelay);
    tailgate::wgengine::ping::StartResult started = m_tracker.Start(
        tailgate::wgengine::ping::Request{
            .Id = requestId,
            .Target = request.Target,
            .PingMode = tailgate::wgengine::ping::Mode::Disco,
            .Timeout = PingExpiry,
            .Relay = std::move(selectedRelay),
        },
        config,
        disco,
        now);
    if (started.Status != tailgate::wgengine::ping::StartStatus::Ready || !started.Outbound)
    {
        const app_service::Status status =
            started.Status == tailgate::wgengine::ping::StartStatus::NoMatchingPeer
                ? app_service::Status::NoMatchingPeer
                : app_service::Status::NoDiscoKey;
        m_logger.LogWarning("app ping could not start target={} status={}",
                            request.Target,
                            static_cast<int>(started.Status));
        respondError(status);
        return;
    }
    m_pending.push_back(PendingResponse{
        .RequestId = requestId,
        .Sequence = request.Sequence,
        .AppAddress = datagram.Source(),
        .AppPort = datagram.SourcePort(),
    });
    AppendRelayFrame(relayOutput,
                     tailgate::hosted::Frame(
                         tailgate::hosted::MessageType::ClientPacket,
                         tailgate::hosted::ProtocolCodec::EncodePeerPacket(
                             tailgate::hosted::PeerPacket(started.Outbound->Peer,
                                                          std::move(started.Outbound->Payload),
                                                          false,
                                                          started.Outbound->Disco))));
    m_logger.LogDebug("app ping sent seq={} target={} app={}:{}",
                      request.Sequence,
                      request.Target,
                      tailgate::net::Ipv4Address::FromHostOrder(datagram.Source()).ToString(),
                      datagram.SourcePort());
}

void PingService::Complete(const tailgate::disco::Disco::Message& message,
                           const tailgate::hosted::PeerPacket& packet)
{
    const auto now = std::chrono::steady_clock::now();
    const std::optional<tailgate::wgengine::ping::Result> result =
        m_tracker.CompleteDisco(packet.Peer(), message.Transaction, 0, now);
    if (!result)
    {
        return;
    }
    const auto pending = std::ranges::find_if(m_pending,
                                              [&](const PendingResponse& candidate)
                                              {
                                                  return candidate.RequestId == result->RequestId;
                                              });
    if (pending == m_pending.end())
    {
        return;
    }
    const auto latency =
        std::chrono::duration_cast<std::chrono::microseconds>(result->Latency).count();
    // The relay server stamps the source endpoint onto peer packets it received over UDP.
    // This describes only the server-to-peer leg; the hosted UWP path remains relayed.
    const bool serverPathDirect = packet.EndpointAddress() != 0 && packet.EndpointPort() != 0;
    const std::string endpoint =
        serverPathDirect
            ? std::format(
                  "{}:{}",
                  tailgate::net::Ipv4Address::FromHostOrder(packet.EndpointAddress()).ToString(),
                  packet.EndpointPort())
            : "";
    if (serverPathDirect)
    {
        m_logger.LogDebug(
            "app ping pong seq={} peer={} latency-us={} relay={} "
            "server-path-endpoint={}:{}",
            pending->Sequence,
            result->PeerName,
            latency,
            result->Relay,
            tailgate::net::Ipv4Address::FromHostOrder(packet.EndpointAddress()).ToString(),
            packet.EndpointPort());
    }
    else
    {
        m_logger.LogDebug("app ping pong seq={} peer={} latency-us={} relay={}",
                          pending->Sequence,
                          result->PeerName,
                          latency,
                          result->Relay);
    }
    m_responses.push_back(BuildResponse(pending->AppAddress,
                                        pending->AppPort,
                                        app_service::Status::Ok,
                                        pending->Sequence,
                                        static_cast<std::uint32_t>(latency),
                                        result->Relay,
                                        endpoint));
    m_pending.erase(pending);
}

} // namespace tailgate::uwp::bg::service
