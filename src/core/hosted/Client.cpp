#include "tailgate/hosted/Client.h"

#include <algorithm>
#include <string_view>
#include <utility>

#include <tailgate/base/Logger.h>
#include <tailgate/derp/Client.h>
#include <tailgate/hosted/DiscoProbes.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/net/packet/Tsmp.h>
#include <tailgate/wgengine/wireguard/Router.h>

namespace tailgate::hosted
{
namespace
{

constexpr std::string_view IdentityChangedMessage = "Tailgate relay changed the client identity.";
constexpr std::string_view NotActiveMessage = "The hosted client is not active.";
constexpr std::string_view NodeKeyPrefix = "nodekey:";
constexpr std::string_view DiscoKeyPrefix = "discokey:";

void AppendFrame(std::vector<std::uint8_t>& output, const Frame& frame)
{
    std::vector<std::uint8_t> encoded = frame.Encode();
    output.insert(output.end(), encoded.begin(), encoded.end());
}

std::vector<std::uint8_t>
EncodeNetworkMapFrame(const tailgate::types::netmap::NetworkConfig& config)
{
    return Frame(MessageType::NetworkMap, ProtocolCodec::EncodeNetworkConfig(config)).Encode();
}

void AppendTransportPackets(
    std::vector<std::uint8_t>& output,
    std::vector<tailgate::wgengine::wireguard::WireGuardRouter::TransportPacket> packets)
{
    for (auto& packet : packets)
    {
        AppendFrame(output,
                    Frame(MessageType::ClientPacket,
                          ProtocolCodec::EncodePeerPacket(
                              PeerPacket(packet.Peer, std::move(packet.Payload), packet.Control))));
    }
}

} // namespace

ClientException::ClientException(ClientError error)
    : std::runtime_error(error == ClientError::IdentityChanged ? IdentityChangedMessage.data()
                                                               : NotActiveMessage.data()),
      m_error(error)
{
}

ClientError ClientException::Error() const noexcept
{
    return m_error;
}

class Client::Impl final
{
public:
    [[nodiscard]] std::vector<std::uint8_t> Start(ClientConfig config)
    {
        Config = std::move(config);
        Router = std::make_unique<tailgate::wgengine::wireguard::WireGuardRouter>(
            Config.NodePrivateKey, Config.Network.Peers(), Config.ExitNode);
        DiscoState =
            std::make_unique<tailgate::disco::Disco>(Config.DiscoPrivateKey, Config.NodePublicKey);
        return EncodeNetworkMapFrame(Config.Network);
    }

    void Stop() noexcept
    {
        Router.reset();
        DiscoState.reset();
        Config = {};
    }

    [[nodiscard]] std::vector<std::uint8_t> Encapsulate(const std::vector<std::uint8_t>& packet)
    {
        std::vector<std::uint8_t> output;
        if (Router)
        {
            AppendTransportPackets(output, Router->Send(packet));
        }
        return output;
    }

    [[nodiscard]] ClientProcessResult Process(const Frame& frame)
    {
        ClientProcessResult result;
        switch (frame.Type())
        {
        case MessageType::ServerPacket:
            ProcessServerPacket(ProtocolCodec::DecodePeerPacket(frame.Payload()), result);
            break;
        case MessageType::NetworkMap:
            (void)UpdateNetworkMap(ProtocolCodec::DecodeNetworkConfig(frame.Payload()),
                                   std::nullopt);
            result.NetworkMapChanged = true;
            break;
        case MessageType::Heartbeat:
            ProcessHeartbeat(result.RemoteOutput);
            break;
        case MessageType::DerpChallenge:
            ProcessDerpChallenge(frame, result.RemoteOutput);
            break;
        default:
            break;
        }
        return result;
    }

    [[nodiscard]] std::vector<std::uint8_t> UpdateTimers()
    {
        std::vector<std::uint8_t> output;
        if (Router)
        {
            AppendTransportPackets(output, Router->UpdateTimers());
        }
        return output;
    }

    [[nodiscard]] std::vector<std::uint8_t> BuildKeepAlive()
    {
        std::vector<std::uint8_t> output = UpdateTimers();
        AppendFrame(output, Frame(MessageType::Heartbeat, {}));
        return output;
    }

    [[nodiscard]] std::vector<std::uint8_t>
    UpdateNetworkMap(tailgate::types::netmap::NetworkConfig config,
                     std::optional<std::string> exitNode)
    {
        if (!Router || config.Domain() != Config.Network.Domain() ||
            config.SelfNodeId() != Config.Network.SelfNodeId() ||
            config.SelfKey() != Config.Network.SelfKey())
        {
            throw ClientException(ClientError::IdentityChanged);
        }
        if (exitNode)
        {
            Config.ExitNode = std::move(*exitNode);
        }
        Config.Network = std::move(config);
        Router->UpdatePeers(Config.Network.Peers(), Config.ExitNode);
        return EncodeNetworkMapFrame(Config.Network);
    }

    void ProcessServerPacket(const PeerPacket& packet, ClientProcessResult& result)
    {
        if (!Router)
        {
            return;
        }
        if (packet.Disco())
        {
            ProcessDiscoPacket(packet, result);
            return;
        }
        const bool hasDirectSource = packet.EndpointAddress() != 0 && packet.EndpointPort() != 0;
        tailgate::wgengine::wireguard::WireGuardRouter::ReceiveResult received =
            hasDirectSource ? Router->Receive(packet.Payload())
                            : Router->Receive(packet.Peer(), packet.Payload());
        AppendTransportPackets(result.RemoteOutput, std::move(received.Outbound));
        for (auto& plaintext : received.Plaintext)
        {
            if (const std::optional<std::vector<std::uint8_t>> pong =
                    tailgate::net::packet::TsmpPacket::BuildPong(plaintext, 0))
            {
                Logger.LogDebug("answering TSMP ping from peer={}",
                                tailgate::crypto::BytesToHex(packet.Peer().data(), 8));
                AppendTransportPackets(result.RemoteOutput, Router->Send(*pong));
                continue;
            }
            result.LocalPackets.push_back(std::move(plaintext));
        }
    }

    void ProcessDiscoPacket(const PeerPacket& packet, ClientProcessResult& result)
    {
        if (!DiscoState)
        {
            Logger.LogDebug("disco packet dropped: no disco state");
            return;
        }
        const std::string nodeKey =
            std::string(NodeKeyPrefix) +
            tailgate::crypto::BytesToHex(packet.Peer().data(), packet.Peer().size());
        const auto peer = std::find_if(Config.Network.Peers().begin(),
                                       Config.Network.Peers().end(),
                                       [&](const tailgate::types::netmap::PeerConfig& candidate)
                                       {
                                           return candidate.Key() == nodeKey;
                                       });
        if (peer == Config.Network.Peers().end() || peer->DiscoKey().rfind(DiscoKeyPrefix, 0) != 0)
        {
            Logger.LogDebug("disco packet dropped: unknown peer or missing disco key {}", nodeKey);
            return;
        }
        const std::vector<std::uint8_t> keyBytes =
            tailgate::crypto::HexToBytes(peer->DiscoKey().substr(DiscoKeyPrefix.size()));
        if (keyBytes.size() != tailgate::crypto::Bytes32{}.size())
        {
            Logger.LogDebug("disco packet dropped: bad disco key length peer={}", peer->Name());
            return;
        }
        tailgate::crypto::Bytes32 discoKey{};
        std::copy(keyBytes.begin(), keyBytes.end(), discoKey.begin());
        const std::optional<tailgate::disco::Disco::Message> message =
            DiscoState->Parse(packet.Payload());
        if (message && message->Sender == discoKey &&
            message->Type == tailgate::disco::Disco::MessageType::Pong)
        {
            result.Pong = DiscoPong{.Message = *message, .Packet = packet};
            if (packet.EndpointAddress() != 0 && packet.EndpointPort() != 0)
            {
                const PeerEndpoint endpoint(
                    packet.Peer(),
                    tailgate::net::Endpoint(
                        tailgate::net::Ipv4Address::FromHostOrder(packet.EndpointAddress()),
                        packet.EndpointPort()));
                AppendFrame(
                    result.RemoteOutput,
                    Frame(MessageType::PeerEndpoint, ProtocolCodec::EncodePeerEndpoint(endpoint)));
            }
            return;
        }
        if (message && message->Sender == discoKey &&
            message->Type == tailgate::disco::Disco::MessageType::CallMeMaybe)
        {
            const tailgate::disco::Disco::TransactionId transaction =
                DiscoState->NewTransactionId();
            const std::vector<std::uint8_t> ping = DiscoState->BuildPing(discoKey, transaction);
            for (const tailgate::net::Endpoint& endpoint : message->Endpoints)
            {
                AppendFrame(
                    result.RemoteOutput,
                    Frame(MessageType::ClientPacket,
                          ProtocolCodec::EncodePeerPacket(PeerPacket(packet.Peer(),
                                                                     ping,
                                                                     false,
                                                                     true,
                                                                     endpoint.Address().HostOrder(),
                                                                     endpoint.Port()))));
            }
            return;
        }
        if (!message || message->Sender != discoKey ||
            message->Type != tailgate::disco::Disco::MessageType::Ping)
        {
            Logger.LogDebug("disco packet dropped: peer={} parsed={} sender-match={}",
                            peer->Name(),
                            message.has_value(),
                            message && message->Sender == discoKey);
            return;
        }
        const bool viaDerp = packet.EndpointAddress() == 0 || packet.EndpointPort() == 0;
        const tailgate::net::Ipv4Address pongAddress =
            viaDerp ? tailgate::disco::Disco::DerpMagicIpv4Address
                    : tailgate::net::Ipv4Address::FromHostOrder(packet.EndpointAddress());
        const std::uint16_t pongPort = viaDerp
                                           ? static_cast<std::uint16_t>(Config.Network.DerpRegion())
                                           : packet.EndpointPort();
        const PeerPacket response(
            packet.Peer(),
            DiscoState->BuildPong(discoKey, message->Transaction, pongAddress, pongPort),
            false,
            true,
            packet.EndpointAddress(),
            packet.EndpointPort());
        AppendFrame(result.RemoteOutput,
                    Frame(MessageType::ClientPacket, ProtocolCodec::EncodePeerPacket(response)));
    }

    void ProcessHeartbeat(std::vector<std::uint8_t>& output)
    {
        AppendFrame(output, Frame(MessageType::Heartbeat, {}));
        if (Router)
        {
            AppendTransportPackets(output, Router->UpdateTimers());
        }
        std::vector<std::uint8_t> probes = ProbePeers();
        output.insert(output.end(), probes.begin(), probes.end());
    }

    [[nodiscard]] std::vector<std::uint8_t> ProbePeers()
    {
        std::vector<std::uint8_t> output;
        if (DiscoState)
        {
            for (const PeerPacket& probe : BuildDiscoProbes(*DiscoState, Config.Network.Peers()))
            {
                AppendFrame(
                    output,
                    Frame(MessageType::ClientPacket, ProtocolCodec::EncodePeerPacket(probe)));
            }
        }
        return output;
    }

    void ProcessDerpChallenge(const Frame& frame, std::vector<std::uint8_t>& output)
    {
        const DerpAuthenticationChallenge challenge =
            ProtocolCodec::DecodeDerpChallenge(frame.Payload());
        const std::vector<std::uint8_t> clientInfo = tailgate::derp::DerpClient::BuildClientInfo(
            Config.NodePrivateKey, Config.NodePublicKey, challenge.ServerKey());
        AppendFrame(output,
                    Frame(MessageType::DerpResponse,
                          ProtocolCodec::EncodeDerpResponse(
                              DerpAuthenticationResponse(challenge.RequestId(), clientInfo))));
    }

    ClientConfig Config;
    std::unique_ptr<tailgate::wgengine::wireguard::WireGuardRouter> Router;
    std::unique_ptr<tailgate::disco::Disco> DiscoState;
    tailgate::base::Logger Logger{"hosted-client"};
};

Client::Client() : m_impl(std::make_unique<Impl>())
{
}

Client::~Client() = default;
Client::Client(Client&&) noexcept = default;
Client& Client::operator=(Client&&) noexcept = default;

std::vector<std::uint8_t> Client::Start(ClientConfig config)
{
    return m_impl->Start(std::move(config));
}

void Client::Stop() noexcept
{
    m_impl->Stop();
}

bool Client::Active() const noexcept
{
    return m_impl->Router != nullptr;
}

const tailgate::types::netmap::NetworkConfig& Client::Network() const
{
    return m_impl->Config.Network;
}

tailgate::disco::Disco& Client::Disco()
{
    if (!m_impl->DiscoState)
    {
        throw ClientException(ClientError::NotActive);
    }
    return *m_impl->DiscoState;
}

const std::string& Client::ExitNode() const noexcept
{
    return m_impl->Config.ExitNode;
}

std::vector<std::uint8_t> Client::Encapsulate(const std::vector<std::uint8_t>& packet)
{
    return m_impl->Encapsulate(packet);
}

ClientProcessResult Client::Process(const Frame& frame)
{
    return m_impl->Process(frame);
}

std::vector<std::uint8_t> Client::UpdateTimers()
{
    return m_impl->UpdateTimers();
}

std::vector<std::uint8_t> Client::BuildKeepAlive()
{
    return m_impl->BuildKeepAlive();
}

std::vector<std::uint8_t> Client::ProbePeers()
{
    return m_impl->ProbePeers();
}

std::vector<std::uint8_t> Client::UpdateNetworkMap(tailgate::types::netmap::NetworkConfig config,
                                                   std::optional<std::string> exitNode)
{
    return m_impl->UpdateNetworkMap(std::move(config), std::move(exitNode));
}

} // namespace tailgate::hosted
