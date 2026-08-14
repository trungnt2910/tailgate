#include "PingService.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include <boost/algorithm/string/case_conv.hpp>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/packet/Ipv4.h>

#include "common/VpnConstants.h"

namespace tailgate::uwp::bg::service
{
namespace
{

constexpr std::chrono::seconds PingExpiry(10);
constexpr std::string_view NodeKeyPrefix = "nodekey:";
constexpr std::string_view DiscoKeyPrefix = "discokey:";

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
    return tailgate::net::packet::BuildUdpPacket(VpnConstants::Network::ServiceIpv4Address,
                                                 appAddress,
                                                 VpnConstants::AppService::Port,
                                                 appPort,
                                                 payload);
}

std::string RelayLabel(const tailgate::types::netmap::PeerConfig& peer,
                       const std::string& relayName)
{
    if (!relayName.empty())
    {
        return relayName;
    }
    std::string result =
        peer.DerpCode.empty() ? std::format("derp-{}", peer.DerpRegion) : peer.DerpCode;
    boost::algorithm::to_upper(result);
    return result;
}

} // namespace

PingService::PingService(manager::DataPlaneManager& dataPlaneManager)
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
}

void PingService::Encapsulate(EncapsulationContext& context)
{
    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> datagram =
        tailgate::net::packet::ParseIpv4UdpDatagram(context.Original);
    if (!datagram || datagram->Destination != VpnConstants::Network::ServiceIpv4Address ||
        datagram->DestinationPort != VpnConstants::AppService::Port)
    {
        return;
    }
    const std::optional<app_service::Message> message =
        app_service::DecodeMessage(datagram->Payload);
    if (!message || message->Type != app_service::MessageType::PingRequest)
    {
        return;
    }
    const std::optional<std::uint32_t> self =
        tailgate::net::packet::ParseIpv4(context.Config.SelfAddress);
    const std::optional<app_service::PingRequest> request =
        app_service::DecodePingRequest(*message);
    if (!self || datagram->Source != *self || datagram->SourcePort == 0 || !request)
    {
        m_logger.LogWarning("discarding invalid in-tunnel ping request");
        return;
    }
    Handle(*datagram,
           *request,
           context.Config,
           context.Disco,
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
                         tailgate::disco::Disco* disco,
                         const std::string& relayName,
                         std::vector<std::uint8_t>& relayOutput,
                         std::vector<std::vector<std::uint8_t>>& appResponses)
{
    const auto now = std::chrono::steady_clock::now();
    std::erase_if(m_pending,
                  [&](const PendingPing& pending)
                  {
                      const bool expired = now - pending.Started > PingExpiry;
                      if (expired)
                      {
                          m_logger.LogDebug("app ping expired without a pong seq={} peer={}",
                                            pending.Sequence,
                                            pending.PeerName);
                      }
                      return expired;
                  });
    const auto respondError = [&](app_service::Status status)
    {
        appResponses.push_back(
            BuildResponse(datagram.Source, datagram.SourcePort, status, request.Sequence));
    };
    const auto peer =
        std::find_if(config.Peers.begin(),
                     config.Peers.end(),
                     [&](const tailgate::types::netmap::PeerConfig& candidate)
                     {
                         return candidate.Address == request.Target ||
                                candidate.Name == request.Target ||
                                std::find(candidate.Addresses.begin(),
                                          candidate.Addresses.end(),
                                          request.Target) != candidate.Addresses.end();
                     });
    if (peer == config.Peers.end())
    {
        m_logger.LogWarning("app ping failed: no matching peer target={}", request.Target);
        respondError(app_service::Status::NoMatchingPeer);
        return;
    }
    const std::vector<std::uint8_t> nodeBytes =
        peer->Key.rfind(NodeKeyPrefix, 0) == 0
            ? tailgate::crypto::HexToBytes(peer->Key.substr(NodeKeyPrefix.size()))
            : std::vector<std::uint8_t>{};
    const std::vector<std::uint8_t> discoBytes =
        peer->DiscoKey.rfind(DiscoKeyPrefix, 0) == 0
            ? tailgate::crypto::HexToBytes(peer->DiscoKey.substr(DiscoKeyPrefix.size()))
            : std::vector<std::uint8_t>{};
    if (!disco || nodeBytes.size() != tailgate::crypto::Bytes32{}.size() ||
        discoBytes.size() != tailgate::crypto::Bytes32{}.size())
    {
        m_logger.LogWarning("app ping failed: peer has no usable disco key peer={}", peer->Name);
        respondError(app_service::Status::NoDiscoKey);
        return;
    }
    PendingPing pending;
    pending.Sequence = request.Sequence;
    pending.Transaction = disco->NewTransactionId();
    pending.Started = now;
    pending.PeerName = peer->Name;
    pending.Relay = RelayLabel(*peer, relayName);
    pending.AppAddress = datagram.Source;
    pending.AppPort = datagram.SourcePort;
    tailgate::crypto::Bytes32 nodeKey{};
    tailgate::crypto::Bytes32 discoKey{};
    std::copy(nodeBytes.begin(), nodeBytes.end(), nodeKey.begin());
    std::copy(discoBytes.begin(), discoBytes.end(), discoKey.begin());
    AppendRelayFrame(relayOutput,
                     tailgate::hosted::Frame{
                         .Type = tailgate::hosted::MessageType::ClientPacket,
                         .Payload = tailgate::hosted::EncodePeerPacket(tailgate::hosted::PeerPacket{
                             .Peer = nodeKey,
                             .Payload = disco->BuildPing(discoKey, pending.Transaction),
                             .Disco = true,
                         }),
                     });
    m_logger.LogDebug("app ping sent seq={} peer={} relay={} app={}:{}",
                      request.Sequence,
                      peer->Name,
                      pending.Relay,
                      tailgate::net::packet::FormatIpv4(pending.AppAddress),
                      pending.AppPort);
    m_pending.push_back(std::move(pending));
}

void PingService::Complete(const tailgate::disco::Disco::Message& message,
                           const tailgate::hosted::PeerPacket& packet)
{
    const auto pending = std::find_if(m_pending.begin(),
                                      m_pending.end(),
                                      [&](const PendingPing& candidate)
                                      {
                                          return candidate.Transaction == message.Transaction;
                                      });
    if (pending == m_pending.end())
    {
        return;
    }
    const auto elapsed = std::chrono::steady_clock::now() - pending->Started;
    const auto latency = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
    // The relay server stamps the source endpoint onto peer packets it received over UDP.
    // This describes only the server-to-peer leg; the hosted UWP path remains relayed.
    const bool serverPathDirect = packet.EndpointAddress != 0 && packet.EndpointPort != 0;
    const std::string endpoint =
        serverPathDirect ? std::format("{}:{}",
                                       tailgate::net::packet::FormatIpv4(packet.EndpointAddress),
                                       packet.EndpointPort)
                         : "";
    if (serverPathDirect)
    {
        m_logger.LogDebug("app ping pong seq={} peer={} latency-us={} relay={} "
                          "server-path-endpoint={}:{}",
                          pending->Sequence,
                          pending->PeerName,
                          latency,
                          pending->Relay,
                          tailgate::net::packet::FormatIpv4(packet.EndpointAddress),
                          packet.EndpointPort);
    }
    else
    {
        m_logger.LogDebug("app ping pong seq={} peer={} latency-us={} relay={}",
                          pending->Sequence,
                          pending->PeerName,
                          latency,
                          pending->Relay);
    }
    m_responses.push_back(BuildResponse(pending->AppAddress,
                                        pending->AppPort,
                                        app_service::Status::Ok,
                                        pending->Sequence,
                                        static_cast<std::uint32_t>(latency),
                                        pending->Relay,
                                        endpoint));
    m_pending.erase(pending);
}

} // namespace tailgate::uwp::bg::service
