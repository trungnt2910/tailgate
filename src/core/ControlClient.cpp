#include "tailgate/control/ControlClient.h"

#include "tailgate/Logging.h"
#include "tailgate/protocol/ControlHandshake.h"
#include "tailgate/protocol/Crypto.h"
#include "tailgate/protocol/H2.h"
#include "tailgate/protocol/NoiseTransport.h"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace tailgate::control
{
namespace
{

constexpr std::size_t H2FrameHeaderSize = 9;
constexpr std::uint32_t MaximumH2FrameLength = 1024U * 1024U;
constexpr std::uint32_t InitialH2WindowSize = 1024U * 1024U;
constexpr std::uint8_t H2EndOrAckFlag = 0x01;
constexpr int MaximumControlResponseFrames = 80;

bool LooksLikeH2(const std::vector<std::uint8_t>& data)
{
    if (data.size() < H2FrameHeaderSize)
    {
        return false;
    }
    const std::uint32_t length = (static_cast<std::uint32_t>(data[0]) << 16) |
                                 (static_cast<std::uint32_t>(data[1]) << 8) | data[2];
    const std::uint8_t type = data[3];
    return length <= MaximumH2FrameLength && (type == 0x00 || type == 0x01 || type == 0x04 ||
                                              type == 0x06 || type == 0x07 || type == 0x08);
}

std::optional<std::string> DescribeIncrementalNetworkMap(const std::string& text)
{
    const nlohmann::json map = nlohmann::json::parse(text, nullptr, false);
    if (map.is_discarded() || !map.is_object() || map.contains("Peers"))
    {
        return std::nullopt;
    }

    const auto count = [&map](const char* key) -> std::size_t
    {
        const auto value = map.find(key);
        if (value == map.end())
        {
            return 0;
        }
        if (value->is_array() || value->is_object())
        {
            return value->size();
        }
        return 1;
    };

    const bool hasIncrementalFields =
        map.value("KeepAlive", false) || map.contains("PingRequest") ||
        map.contains("PeersChanged") || map.contains("PeersRemoved") ||
        map.contains("PeersChangedPatch") || map.contains("PeerSeenChange") ||
        map.contains("OnlineChange") || map.contains("DERPMap") || map.contains("DNSConfig") ||
        map.contains("Domain");
    if (!hasIncrementalFields)
    {
        return std::nullopt;
    }

    std::ostringstream description;
    description << "incremental network-map update:";
    if (map.value("KeepAlive", false))
    {
        description << " keepalive";
    }
    if (map.contains("Seq"))
    {
        description << " seq=" << map.at("Seq");
    }
    description << " peers_changed=" << count("PeersChanged");
    description << " peers_removed=" << count("PeersRemoved");
    description << " peer_patches=" << count("PeersChangedPatch");
    description << " online_changes=" << count("OnlineChange");
    description << " seen_changes=" << count("PeerSeenChange");
    if (map.contains("DERPMap"))
    {
        description << " derp_map";
    }
    if (map.contains("DNSConfig"))
    {
        description << " dns_config";
    }
    if (map.contains("PingRequest"))
    {
        description << " ping_request";
    }
    return description.str();
}

} // namespace

class ControlClient::Impl
{
public:
    Impl(IByteStream& stream,
         const protocol::Bytes32& machinePrivateKey,
         const protocol::Bytes32& nodePrivateKey,
         protocol::HostInfo host)
        : Host(std::move(host)),
          NodePublic(protocol::X25519PublicFromPrivate(nodePrivateKey)),
          NodeKey("nodekey:" + protocol::BytesToHex(NodePublic.data(), NodePublic.size()))
    {
        const protocol::Bytes32 ephemeralKey = protocol::GeneratePrivateKey();
        protocol::ControlHandshake handshake(machinePrivateKey, ephemeralKey);
        protocol::ControlHandshakeResult result =
            handshake.Run(stream, protocol::ControlHandshake::DefaultHost);
        Transport = std::make_unique<protocol::NoiseTransport>(stream, result.Keys);
        Transport->Send(protocol::BuildH2Preface(InitialH2WindowSize));
    }

    std::vector<std::uint8_t> Request(std::uint32_t streamId,
                                      const std::string& path,
                                      const std::vector<std::uint8_t>& body,
                                      bool waitForResponse)
    {
        std::vector<std::uint8_t> request =
            protocol::BuildH2Headers("POST",
                                     path,
                                     protocol::ControlHandshake::DefaultHost,
                                     "application/json",
                                     {{"ts-lb", NodeKey}},
                                     streamId,
                                     false);
        std::vector<std::uint8_t> data = protocol::BuildH2Data(body, streamId, true);
        request.insert(request.end(), data.begin(), data.end());
        Transport->Send(request);
        if (!waitForResponse)
        {
            return {};
        }

        std::vector<std::uint8_t> response;
        for (int attempt = 0; attempt < MaximumControlResponseFrames; ++attempt)
        {
            std::vector<std::uint8_t> plaintext = Transport->Receive();
            if (H2Buffer.empty() && !LooksLikeH2(plaintext))
            {
                continue;
            }
            H2Buffer.insert(H2Buffer.end(), plaintext.begin(), plaintext.end());
            for (const protocol::H2Frame& frame : protocol::TakeCompleteH2Frames(H2Buffer))
            {
                if (frame.Type == protocol::H2FrameType::Settings &&
                    (frame.Flags & H2EndOrAckFlag) == 0)
                {
                    Transport->Send(protocol::BuildH2SettingsAck());
                }
                if (frame.Type == protocol::H2FrameType::Data && frame.StreamId == streamId)
                {
                    response.insert(response.end(), frame.Payload.begin(), frame.Payload.end());
                }
                if (frame.StreamId == streamId && (frame.Flags & H2EndOrAckFlag) != 0)
                {
                    return response;
                }
            }
        }
        throw std::runtime_error("control response did not finish");
    }

    protocol::HostInfo Host;
    protocol::Bytes32 NodePublic{};
    std::string NodeKey;
    protocol::Bytes32 DiscoPrivate{};
    std::string DiscoKey;
    std::uint32_t NextStreamId = 1;
    std::uint32_t MapStreamId = 0;
    std::vector<std::uint8_t> H2Buffer;
    std::vector<std::uint8_t> MapBody;
    std::optional<NetworkConfig> CurrentMap;
    std::unique_ptr<protocol::NoiseTransport> Transport;
};

ControlClient::ControlClient(IByteStream& stream,
                             const protocol::Bytes32& machinePrivateKey,
                             const protocol::Bytes32& nodePrivateKey,
                             const protocol::HostInfo& host)
    : Implementation(std::make_unique<Impl>(stream, machinePrivateKey, nodePrivateKey, host))
{
}

ControlClient::~ControlClient() = default;
ControlClient::ControlClient(ControlClient&&) noexcept = default;
ControlClient& ControlClient::operator=(ControlClient&&) noexcept = default;

NetworkConfig ControlClient::RegisterAndGetNetworkMap(const std::string& authKey)
{
    (void)Implementation->Request(
        Implementation->NextStreamId,
        "/machine/register",
        protocol::BuildRegisterRequest(Implementation->NodeKey, authKey, Implementation->Host),
        true);
    Log(LogLevel::Info, "control", "node registration accepted");
    Implementation->NextStreamId += 2;

    if (std::all_of(Implementation->DiscoPrivate.begin(),
                    Implementation->DiscoPrivate.end(),
                    [](std::uint8_t byte)
                    {
                        return byte == 0;
                    }))
    {
        Implementation->DiscoPrivate = protocol::GeneratePrivateKey();
    }
    const protocol::Bytes32 discoPublic =
        protocol::X25519PublicFromPrivate(Implementation->DiscoPrivate);
    Implementation->DiscoKey =
        "discokey:" + protocol::BytesToHex(discoPublic.data(), discoPublic.size());
    std::vector<std::uint8_t> body = Implementation->Request(
        Implementation->NextStreamId,
        "/machine/map",
        protocol::BuildMapRequest(
            Implementation->NodeKey, Implementation->DiscoKey, Implementation->Host),
        true);
    Implementation->NextStreamId += 2;

    const auto start = std::find(body.begin(), body.end(), static_cast<std::uint8_t>('{'));
    if (start == body.end())
    {
        throw std::runtime_error("control map response did not contain JSON");
    }
    const std::size_t jsonOffset = static_cast<std::size_t>(start - body.begin());
    std::size_t jsonLength = body.size() - jsonOffset;
    if (jsonOffset >= 4)
    {
        const std::size_t framedLength = (static_cast<std::size_t>(body[jsonOffset - 4]) << 24U) |
                                         (static_cast<std::size_t>(body[jsonOffset - 3]) << 16U) |
                                         (static_cast<std::size_t>(body[jsonOffset - 2]) << 8U) |
                                         body[jsonOffset - 1];
        if (framedLength > 0 && jsonOffset + framedLength <= body.size())
        {
            jsonLength = framedLength;
        }
    }
    NetworkConfig config =
        ParseNetworkMap(std::string(start, start + static_cast<std::ptrdiff_t>(jsonLength)));
    Log(LogLevel::Info,
        "control",
        "network map received: address=" + config.SelfAddress +
            " peers=" + std::to_string(config.Peers.size()) + " derp=" + config.DerpCode +
            " dns=" + config.DnsResolver);
    Implementation->CurrentMap = config;
    return config;
}

void ControlClient::SetDiscoPrivateKey(const protocol::Bytes32& privateKey)
{
    Implementation->DiscoPrivate = privateKey;
}

void ControlClient::SetPreferredDerp(int region)
{
    (void)Implementation->Request(
        Implementation->NextStreamId,
        "/machine/map",
        protocol::BuildMapRequest(
            Implementation->NodeKey, Implementation->DiscoKey, Implementation->Host, region),
        true);
    Implementation->NextStreamId += 2;
    Log(LogLevel::Debug, "control", "preferred DERP set to " + std::to_string(region));

    (void)Implementation->Request(
        Implementation->NextStreamId,
        "/machine/map",
        protocol::BuildMapRequest(
            Implementation->NodeKey, Implementation->DiscoKey, Implementation->Host, region, true),
        false);
    Implementation->MapStreamId = Implementation->NextStreamId;
    Implementation->NextStreamId += 2;
    Log(LogLevel::Info, "control", "streaming network map started");
}

std::optional<NetworkConfig> ControlClient::PollNetworkMap()
{
    constexpr std::size_t mapLengthSize = 4;
    constexpr std::size_t maximumMapSize = 16U * 1024U * 1024U;
    Implementation->Transport->Flush();
    while (true)
    {
        std::optional<std::vector<std::uint8_t>> plaintext =
            Implementation->Transport->TryReceive();
        if (!plaintext)
        {
            break;
        }
        Implementation->H2Buffer.insert(
            Implementation->H2Buffer.end(), plaintext->begin(), plaintext->end());
    }
    for (const protocol::H2Frame& frame : protocol::TakeCompleteH2Frames(Implementation->H2Buffer))
    {
        if (frame.Type == protocol::H2FrameType::Settings && (frame.Flags & H2EndOrAckFlag) == 0)
        {
            Implementation->Transport->Send(protocol::BuildH2SettingsAck());
        }
        else if (frame.Type == protocol::H2FrameType::Ping && (frame.Flags & H2EndOrAckFlag) == 0)
        {
            Implementation->Transport->Send(protocol::BuildH2PingAck(frame.Payload));
        }
        else if (frame.Type == protocol::H2FrameType::GoAway)
        {
            throw std::runtime_error("control server closed the HTTP/2 connection");
        }
        else if (frame.Type == protocol::H2FrameType::Data &&
                 frame.StreamId == Implementation->MapStreamId)
        {
            Implementation->MapBody.insert(
                Implementation->MapBody.end(), frame.Payload.begin(), frame.Payload.end());
            if (!frame.Payload.empty())
            {
                Implementation->Transport->Send(protocol::BuildH2WindowUpdate(
                    0, static_cast<std::uint32_t>(frame.Payload.size())));
                Implementation->Transport->Send(protocol::BuildH2WindowUpdate(
                    frame.StreamId, static_cast<std::uint32_t>(frame.Payload.size())));
            }
        }
    }
    if (Implementation->MapBody.size() < mapLengthSize)
    {
        return std::nullopt;
    }
    const std::size_t mapSize = Implementation->MapBody[0] |
                                (static_cast<std::size_t>(Implementation->MapBody[1]) << 8U) |
                                (static_cast<std::size_t>(Implementation->MapBody[2]) << 16U) |
                                (static_cast<std::size_t>(Implementation->MapBody[3]) << 24U);
    if (mapSize > maximumMapSize)
    {
        throw std::runtime_error("streaming network map exceeds the protocol limit");
    }
    if (Implementation->MapBody.size() < mapLengthSize + mapSize)
    {
        return std::nullopt;
    }
    const std::string json(
        Implementation->MapBody.begin() + static_cast<std::ptrdiff_t>(mapLengthSize),
        Implementation->MapBody.begin() + static_cast<std::ptrdiff_t>(mapLengthSize + mapSize));
    Implementation->MapBody.erase(Implementation->MapBody.begin(),
                                  Implementation->MapBody.begin() +
                                      static_cast<std::ptrdiff_t>(mapLengthSize + mapSize));
    if (std::optional<std::string> incremental = DescribeIncrementalNetworkMap(json))
    {
        Log(LogLevel::Debug, "control", *incremental);
        if (Implementation->CurrentMap && ApplyNetworkMapUpdate(*Implementation->CurrentMap, json))
        {
            return Implementation->CurrentMap;
        }
        return std::nullopt;
    }
    try
    {
        NetworkConfig config = ParseNetworkMap(json);
        Implementation->CurrentMap = config;
        return config;
    }
    catch (const std::exception& error)
    {
        Log(LogLevel::Debug,
            "control",
            "consumed incremental network-map update: " + std::string(error.what()));
        return std::nullopt;
    }
}

void ControlClient::Logout()
{
    (void)Implementation->Request(
        Implementation->NextStreamId,
        "/machine/register",
        protocol::BuildLogoutRequest(Implementation->NodeKey, Implementation->Host),
        true);
    Implementation->NextStreamId += 2;
    Log(LogLevel::Info, "control", "node expiry accepted");
}

const protocol::Bytes32& ControlClient::NodePublicKey() const
{
    return Implementation->NodePublic;
}

const protocol::Bytes32& ControlClient::DiscoPrivateKey() const
{
    return Implementation->DiscoPrivate;
}

} // namespace tailgate::control
