#include "NetworkService.h"

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/derp/Client.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/net/packet/Tsmp.h>
#include <tailgate/types/netmap/NetworkMap.h>

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
    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> datagram =
        tailgate::net::packet::ParseIpv4UdpDatagram(context.Original);
    if (datagram && ((datagram->Destination == VpnConstants::Network::ServiceIpv4Address &&
                      datagram->DestinationPort == VpnConstants::AppService::Port) ||
                     (datagram->Destination == tailgate::net::dns::MagicDnsIpv4Address &&
                      datagram->DestinationPort == tailgate::net::dns::DnsPort)))
    {
        return;
    }
    AppendTransportFrames(context.RemoteOutput, context.Router->Send(context.Original));
}

void NetworkService::Decapsulate(DecapsulationContext& context)
{
    const tailgate::hosted::Frame& frame = context.Message;
    if (frame.Type == tailgate::hosted::MessageType::ServerPacket && context.Router)
    {
        const tailgate::hosted::PeerPacket packet =
            tailgate::hosted::DecodePeerPacket(frame.Payload);
        if (packet.Disco)
        {
            ProcessDiscoPacket(packet, context);
            return;
        }
        auto received = context.Router->Receive(packet.Peer, packet.Payload);
        AppendTransportFrames(context.RemoteOutput, std::move(received.Outbound));
        for (auto& plaintext : received.Plaintext)
        {
            if (const auto pong = tailgate::net::packet::BuildTsmpPong(plaintext, 0))
            {
                m_logger.LogDebug("answering TSMP ping from peer={}",
                                  tailgate::crypto::BytesToHex(packet.Peer.data(), 8));
                AppendTransportFrames(context.RemoteOutput, context.Router->Send(*pong));
                continue;
            }
            context.LocalOutput.push_back(std::move(plaintext));
        }
        return;
    }
    if (frame.Type == tailgate::hosted::MessageType::NetworkMap && context.Router)
    {
        tailgate::types::netmap::NetworkConfig next =
            tailgate::hosted::DecodeNetworkConfig(frame.Payload);
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
    if (frame.Type == tailgate::hosted::MessageType::Heartbeat)
    {
        AppendRelayFrame(context.RemoteOutput,
                         tailgate::hosted::Frame{
                             .Type = tailgate::hosted::MessageType::Heartbeat,
                             .Payload = {},
                         });
        if (context.Router)
        {
            AppendTransportFrames(context.RemoteOutput, context.Router->UpdateTimers());
        }
        if (context.Disco)
        {
            for (const tailgate::hosted::PeerPacket& probe :
                 tailgate::hosted::BuildDiscoProbes(*context.Disco, context.Config.Peers))
            {
                AppendRelayFrame(context.RemoteOutput,
                                 tailgate::hosted::Frame{
                                     .Type = tailgate::hosted::MessageType::ClientPacket,
                                     .Payload = tailgate::hosted::EncodePeerPacket(probe),
                                 });
            }
        }
        return;
    }
    if (frame.Type == tailgate::hosted::MessageType::DerpChallenge)
    {
        const auto challenge = tailgate::hosted::DecodeDerpChallenge(frame.Payload);
        const std::vector<std::uint8_t> clientInfo = tailgate::derp::DerpClient::BuildClientInfo(
            context.NodePrivateKey, context.NodePublicKey, challenge.ServerKey);
        AppendRelayFrame(context.RemoteOutput,
                         tailgate::hosted::Frame{
                             .Type = tailgate::hosted::MessageType::DerpResponse,
                             .Payload = tailgate::hosted::EncodeDerpResponse(
                                 tailgate::hosted::DerpAuthenticationResponse{
                                     .RequestId = challenge.RequestId,
                                     .ClientInfo = clientInfo,
                                 }),
                         });
    }
}

void NetworkService::FlushLocal(std::vector<std::vector<std::uint8_t>>&)
{
}

void NetworkService::ProcessDiscoPacket(const tailgate::hosted::PeerPacket& packet,
                                        DecapsulationContext& context)
{
    if (!context.Disco)
    {
        m_logger.LogDebug("disco packet dropped: no disco state");
        return;
    }
    const std::string nodeKey =
        "nodekey:" + tailgate::crypto::BytesToHex(packet.Peer.data(), packet.Peer.size());
    const auto peer = std::find_if(context.Config.Peers.begin(),
                                   context.Config.Peers.end(),
                                   [&](const tailgate::types::netmap::PeerConfig& candidate)
                                   {
                                       return candidate.Key == nodeKey;
                                   });
    if (peer == context.Config.Peers.end() || peer->DiscoKey.rfind("discokey:", 0) != 0)
    {
        m_logger.LogDebug("disco packet dropped: unknown peer or missing disco key {}", nodeKey);
        return;
    }
    const std::vector<std::uint8_t> keyBytes =
        tailgate::crypto::HexToBytes(peer->DiscoKey.substr(9));
    if (keyBytes.size() != tailgate::crypto::Bytes32{}.size())
    {
        m_logger.LogDebug("disco packet dropped: bad disco key length peer={}", peer->Name);
        return;
    }
    tailgate::crypto::Bytes32 discoKey{};
    std::copy(keyBytes.begin(), keyBytes.end(), discoKey.begin());
    const std::optional<tailgate::disco::Disco::Message> message =
        context.Disco->Parse(packet.Payload);
    if (message && message->Sender == discoKey &&
        message->Type == tailgate::disco::Disco::MessageType::Pong)
    {
        m_logger.LogTrace("disco pong peer={}", peer->Name);
        m_pingService.Complete(*message, packet);
        return;
    }
    if (!message || message->Sender != discoKey ||
        message->Type != tailgate::disco::Disco::MessageType::Ping)
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
                      tailgate::net::packet::FormatIpv4(packet.EndpointAddress),
                      packet.EndpointPort);
    const bool viaDerp = packet.EndpointAddress == 0 || packet.EndpointPort == 0;
    const std::uint32_t pongAddress =
        viaDerp ? tailgate::disco::Disco::DerpMagicIpv4Address : packet.EndpointAddress;
    const std::uint16_t pongPort =
        viaDerp ? static_cast<std::uint16_t>(context.Config.DerpRegion) : packet.EndpointPort;
    const tailgate::hosted::PeerPacket response{
        .Peer = packet.Peer,
        .Payload = context.Disco->BuildPong(discoKey, message->Transaction, pongAddress, pongPort),
        .Disco = true,
        .EndpointAddress = packet.EndpointAddress,
        .EndpointPort = packet.EndpointPort,
    };
    AppendRelayFrame(context.RemoteOutput,
                     tailgate::hosted::Frame{
                         .Type = tailgate::hosted::MessageType::ClientPacket,
                         .Payload = tailgate::hosted::EncodePeerPacket(response),
                     });
}

} // namespace tailgate::uwp::bg::service
