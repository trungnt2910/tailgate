#include "NetworkService.h"

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/control/NetworkMap.h>
#include <tailgate/network/Ipv4.h>
#include <tailgate/network/TailnetDns.h>
#include <tailgate/protocol/Crypto.h>
#include <tailgate/protocol/DerpClient.h>
#include <tailgate/protocol/Tsmp.h>
#include <tailgate/relay/RelayProtocol.h>

#include "common/UwpAppServiceProtocol.h"
#include "common/VpnConstants.h"

#include "PingService.h"

namespace tailgate::uwp::bg::service
{

NetworkService::NetworkService(manager::DataPlaneManager& dataPlaneManager,
                               manager::SessionManager& sessionManager,
                               PingService& pingService)
    : m_pingService(pingService), m_sessionManager(sessionManager)
{
    dataPlaneManager.Register(*this);
}

void NetworkService::Start(SessionGeneration)
{
}

void NetworkService::Stop()
{
}

void NetworkService::Reset()
{
}

void NetworkService::Encapsulate(EncapsulationContext& context)
{
    if (!context.Router)
    {
        return;
    }
    const std::optional<network::Ipv4UdpDatagram> datagram =
        network::ParseIpv4UdpDatagram(context.Original);
    if (datagram && ((datagram->Destination == VpnConstants::Network::ServiceIpv4Address &&
                      datagram->DestinationPort == VpnConstants::AppService::Port) ||
                     (datagram->Destination == network::MagicDnsIpv4Address &&
                      datagram->DestinationPort == network::DnsPort)))
    {
        return;
    }
    AppendTransportFrames(context.RemoteOutput, context.Router->Send(context.Original));
}

void NetworkService::Decapsulate(DecapsulationContext& context)
{
    const relay::Frame& frame = context.Message;
    if (frame.Type == relay::MessageType::ServerPacket && context.Router)
    {
        const relay::PeerPacket packet = relay::DecodePeerPacket(frame.Payload);
        if (packet.Disco)
        {
            ProcessDiscoPacket(packet, context);
            return;
        }
        auto received = context.Router->Receive(packet.Peer, packet.Payload);
        AppendTransportFrames(context.RemoteOutput, std::move(received.Outbound));
        for (auto& plaintext : received.Plaintext)
        {
            if (const auto pong = protocol::BuildTsmpPong(plaintext, 0))
            {
                m_logger.LogDebug("answering TSMP ping from peer={}",
                                  protocol::BytesToHex(packet.Peer.data(), 8));
                AppendTransportFrames(context.RemoteOutput, context.Router->Send(*pong));
                continue;
            }
            context.LocalOutput.push_back(std::move(plaintext));
        }
        return;
    }
    if (frame.Type == relay::MessageType::NetworkMap && context.Router)
    {
        control::NetworkConfig next = relay::DecodeNetworkConfig(frame.Payload);
        if (next.Domain != context.Config.Domain || next.SelfNodeId != context.Config.SelfNodeId ||
            next.SelfKey != context.Config.SelfKey)
        {
            throw std::runtime_error("Tailgate relay changed the client identity.");
        }
        context.Config = std::move(next);
        context.Router->UpdatePeers(context.Config.Peers, context.ExitNode);
        m_sessionManager.WriteState(context.Config);
        return;
    }
    if (frame.Type == relay::MessageType::Heartbeat)
    {
        AppendRelayFrame(context.RemoteOutput,
                         relay::Frame{
                             .Type = relay::MessageType::Heartbeat,
                             .Payload = {},
                         });
        if (context.Router)
        {
            AppendTransportFrames(context.RemoteOutput, context.Router->UpdateTimers());
        }
        if (context.Disco)
        {
            for (const relay::PeerPacket& probe :
                 relay::BuildDiscoProbes(*context.Disco, context.Config.Peers))
            {
                AppendRelayFrame(context.RemoteOutput,
                                 relay::Frame{
                                     .Type = relay::MessageType::ClientPacket,
                                     .Payload = relay::EncodePeerPacket(probe),
                                 });
            }
        }
        return;
    }
    if (frame.Type == relay::MessageType::DerpChallenge)
    {
        const auto challenge = relay::DecodeDerpChallenge(frame.Payload);
        const std::vector<std::uint8_t> clientInfo = protocol::DerpClient::BuildClientInfo(
            context.NodePrivateKey, context.NodePublicKey, challenge.ServerKey);
        AppendRelayFrame(context.RemoteOutput,
                         relay::Frame{
                             .Type = relay::MessageType::DerpResponse,
                             .Payload = relay::EncodeDerpResponse(relay::DerpAuthenticationResponse{
                                 .RequestId = challenge.RequestId,
                                 .ClientInfo = clientInfo,
                             }),
                         });
    }
}

void NetworkService::FlushLocal(std::vector<std::vector<std::uint8_t>>&)
{
}

void NetworkService::ProcessDiscoPacket(const relay::PeerPacket& packet,
                                        DecapsulationContext& context)
{
    if (!context.Disco)
    {
        m_logger.LogDebug("disco packet dropped: no disco state");
        return;
    }
    const std::string nodeKey =
        "nodekey:" + protocol::BytesToHex(packet.Peer.data(), packet.Peer.size());
    const auto peer = std::find_if(context.Config.Peers.begin(),
                                   context.Config.Peers.end(),
                                   [&](const control::PeerConfig& candidate)
                                   {
                                       return candidate.Key == nodeKey;
                                   });
    if (peer == context.Config.Peers.end() || peer->DiscoKey.rfind("discokey:", 0) != 0)
    {
        m_logger.LogDebug("disco packet dropped: unknown peer or missing disco key {}", nodeKey);
        return;
    }
    const std::vector<std::uint8_t> keyBytes = protocol::HexToBytes(peer->DiscoKey.substr(9));
    if (keyBytes.size() != protocol::Bytes32{}.size())
    {
        m_logger.LogDebug("disco packet dropped: bad disco key length peer={}", peer->Name);
        return;
    }
    protocol::Bytes32 discoKey{};
    std::copy(keyBytes.begin(), keyBytes.end(), discoKey.begin());
    const std::optional<protocol::Disco::Message> message = context.Disco->Parse(packet.Payload);
    if (message && message->Sender == discoKey &&
        message->Type == protocol::Disco::MessageType::Pong)
    {
        m_logger.LogTrace("disco pong peer={}", peer->Name);
        m_pingService.Complete(*message, packet);
        return;
    }
    if (!message || message->Sender != discoKey ||
        message->Type != protocol::Disco::MessageType::Ping)
    {
        if (message)
        {
            m_logger.LogDebug("disco packet dropped: peer={} parsed=true sender-match={} type={}",
                              peer->Name,
                              message->Sender == discoKey,
                              static_cast<int>(message->Type));
        }
        else
        {
            m_logger.LogDebug("disco packet dropped: peer={} parsed=false", peer->Name);
        }
        return;
    }
    m_logger.LogTrace("disco ping peer={} endpoint={}:{}",
                      peer->Name,
                      network::FormatIpv4(packet.EndpointAddress),
                      packet.EndpointPort);
    const bool viaDerp = packet.EndpointAddress == 0 || packet.EndpointPort == 0;
    const std::uint32_t pongAddress =
        viaDerp ? protocol::Disco::DerpMagicIpv4Address : packet.EndpointAddress;
    const std::uint16_t pongPort =
        viaDerp ? static_cast<std::uint16_t>(context.Config.DerpRegion) : packet.EndpointPort;
    const relay::PeerPacket response{
        .Peer = packet.Peer,
        .Payload = context.Disco->BuildPong(discoKey, message->Transaction, pongAddress, pongPort),
        .Disco = true,
        .EndpointAddress = packet.EndpointAddress,
        .EndpointPort = packet.EndpointPort,
    };
    AppendRelayFrame(context.RemoteOutput,
                     relay::Frame{
                         .Type = relay::MessageType::ClientPacket,
                         .Payload = relay::EncodePeerPacket(response),
                     });
}

} // namespace tailgate::uwp::bg::service
