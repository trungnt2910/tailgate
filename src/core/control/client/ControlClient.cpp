#include <tailgate/control/client/ControlClient.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <format>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <tailgate/base/Logging.h>
#include <tailgate/base/Strings.h>
#include <tailgate/control/base/ControlHandshake.h>
#include <tailgate/control/base/H2.h>
#include <tailgate/control/base/NoiseTransport.h>
#include <tailgate/control/client/NetworkMapParser.h>
#include <tailgate/crypto/Base64.h>
#include <tailgate/crypto/Crypto.h>

namespace tailgate::control::client
{

using tailgate::base::IByteStream;
using tailgate::base::Log;
using tailgate::base::LogLevel;
using tailgate::base::TrimEnd;
using tailgate::control::base::ControlHandshake;
using tailgate::control::base::ControlHandshakeResult;
using tailgate::control::base::NoiseTransport;
using tailgate::types::netmap::NetworkConfig;

namespace
{

constexpr std::size_t H2FrameHeaderSize = 9;
constexpr std::uint32_t MaximumH2FrameLength = 1024U * 1024U;
constexpr std::uint32_t InitialH2WindowSize = 1024U * 1024U;
constexpr std::uint8_t H2EndOrAckFlag = 0x01;
constexpr int MaximumControlResponseFrames = 80;
constexpr std::size_t MapLengthSize = 4;
constexpr std::size_t MaximumSmallHpackLiteral = 127;
constexpr int MaximumInitialMapAttempts = 12;
constexpr std::chrono::milliseconds InitialMapRetryDelay{250};
constexpr std::chrono::milliseconds MaximumMapRetryDelay{2000};
constexpr std::chrono::seconds UnchangedAuthorizationUrlRetryDelay{5};
constexpr std::chrono::seconds DefaultRegistrationRateLimitRetryDelay{5};
constexpr std::chrono::hours MaximumRegistrationRateLimitRetryDelay{1};
constexpr std::size_t MaximumStreamingMapSize = 16U * 1024U * 1024U;

std::string ControlHttpErrorMessage(const std::string& path, int status, std::string_view body)
{
    const std::string_view trimmedBody = TrimEnd(body);
    if (trimmedBody.empty())
    {
        return std::format("Control request {} failed with HTTP status {}.", path, status);
    }
    return std::format(
        "Control request {} failed with HTTP status {}: {}.", path, status, trimmedBody);
}

class ControlHttpError final : public std::runtime_error
{
public:
    ControlHttpError(const std::string& path,
                     int status,
                     std::string body,
                     std::optional<std::uint32_t> retryAfterSeconds)
        : std::runtime_error(ControlHttpErrorMessage(path, status, body)),
          Status(status),
          Body(std::move(body)),
          RetryAfterSeconds(retryAfterSeconds)
    {
    }

    int Status;
    std::string Body;
    std::optional<std::uint32_t> RetryAfterSeconds;
};

std::chrono::milliseconds
RegistrationRateLimitRetryDelay(std::optional<std::uint32_t> retryAfterSeconds)
{
    if (!retryAfterSeconds || *retryAfterSeconds == 0)
    {
        return DefaultRegistrationRateLimitRetryDelay;
    }

    const std::chrono::seconds requestedDelay{*retryAfterSeconds};
    if (requestedDelay > MaximumRegistrationRateLimitRetryDelay)
    {
        return DefaultRegistrationRateLimitRetryDelay;
    }
    return requestedDelay;
}

std::optional<std::uint32_t>
ControlRetryAfterSeconds(const tailgate::control::base::H2Headers& responseHeaders)
{
    const auto [begin, end] = responseHeaders.equal_range("retry-after");
    for (auto header = begin; header != end; ++header)
    {
        std::uint32_t seconds = 0;
        const auto parseResult = std::from_chars(
            header->second.data(), header->second.data() + header->second.size(), seconds);
        if (parseResult.ec == std::errc{} &&
            parseResult.ptr == header->second.data() + header->second.size())
        {
            return seconds;
        }
    }
    return std::nullopt;
}

std::string UrlPathAndQuery(const std::string& url)
{
    const std::size_t scheme = url.find("://");
    std::size_t pathStart = 0;
    if (scheme != std::string::npos)
    {
        pathStart = url.find('/', scheme + 3);
    }
    if (pathStart == std::string::npos)
    {
        return "/";
    }
    std::string path = url.substr(pathStart);
    if (path.empty())
    {
        return "/";
    }
    return path;
}

std::optional<std::string> HttpRequestPath(const std::vector<std::uint8_t>& payload)
{
    const std::string text(payload.begin(), payload.end());
    const std::size_t lineEnd = text.find("\r\n");
    const std::string firstLine = text.substr(0, lineEnd);
    const std::size_t methodEnd = firstLine.find(' ');
    if (methodEnd == std::string::npos)
    {
        return std::nullopt;
    }
    const std::size_t pathStart = methodEnd + 1;
    const std::size_t pathEnd = firstLine.find(' ', pathStart);
    if (pathEnd == std::string::npos || pathEnd == pathStart)
    {
        return std::nullopt;
    }
    std::string path = firstLine.substr(pathStart, pathEnd - pathStart);
    const std::size_t queryStart = path.find('?');
    if (queryStart != std::string::npos)
    {
        path.resize(queryStart);
    }
    return path;
}

std::vector<std::uint8_t> HttpJsonResponse(const std::string& body, int status, std::string reason)
{
    const std::string text = std::format(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status,
        reason,
        body.size(),
        body);
    return {text.begin(), text.end()};
}

std::optional<std::vector<std::uint8_t>> BuildC2NResponse(const nlohmann::json& pingRequest)
{
    if (!pingRequest.is_object() || pingRequest.value("Types", "") != "c2n")
    {
        return std::nullopt;
    }
    const std::string payload = pingRequest.value("Payload", "");
    if (payload.empty())
    {
        return std::nullopt;
    }

    std::vector<std::uint8_t> decoded = tailgate::crypto::Base64Decode(payload);
    std::optional<std::string> path = HttpRequestPath(decoded);
    if (!path)
    {
        return std::nullopt;
    }
    if (*path == "/tls-cert-status")
    {
        return HttpJsonResponse(R"({"Error":"no certificate","Missing":true})", 200, "OK");
    }
    if (*path == "/vip-services")
    {
        return HttpJsonResponse(R"({"VIPServices":[],"ServicesHash":""})", 200, "OK");
    }
    return HttpJsonResponse(R"({"Error":"unhandled c2n request"})", 404, "Not Found");
}

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

    std::string description = "incremental network-map update:";
    if (map.value("KeepAlive", false))
    {
        description += " keepalive";
    }
    if (map.contains("Seq"))
    {
        description += std::format(" seq={}", map.at("Seq").dump());
    }
    description +=
        std::format(" peers_changed={} peers_removed={} peer_patches={} online_changes={} "
                    "seen_changes={}",
                    count("PeersChanged"),
                    count("PeersRemoved"),
                    count("PeersChangedPatch"),
                    count("OnlineChange"),
                    count("PeerSeenChange"));
    if (map.contains("DERPMap"))
    {
        description += " derp_map";
    }
    if (map.contains("DNSConfig"))
    {
        description += " dns_config";
    }
    if (map.contains("PingRequest"))
    {
        description += " ping_request";
        const nlohmann::json& pingRequest = map.at("PingRequest");
        if (pingRequest.is_object())
        {
            description += std::format("(types={} noise={})",
                                       pingRequest.value("Types", ""),
                                       pingRequest.value("URLIsNoise", false) ? 1 : 0);
        }
    }
    const auto patches = map.find("PeersChangedPatch");
    if (patches != map.end() && patches->is_array())
    {
        description += " patches=[";
        bool firstPatch = true;
        for (const nlohmann::json& patch : *patches)
        {
            if (!patch.is_object())
            {
                continue;
            }
            if (!firstPatch)
            {
                description += ';';
            }
            firstPatch = false;
            description += std::format("{}:", patch.value("NodeID", 0ULL));
            bool firstField = true;
            for (const auto& [field, value] : patch.items())
            {
                (void)value;
                if (field == "NodeID")
                {
                    continue;
                }
                if (!firstField)
                {
                    description += ',';
                }
                firstField = false;
                description += field;
            }
        }
        description += ']';
    }
    return description;
}

NetworkConfig ParseMapResponseBody(const std::vector<std::uint8_t>& body)
{
    const auto start = std::find(body.begin(), body.end(), static_cast<std::uint8_t>('{'));
    if (start == body.end())
    {
        throw std::runtime_error("Control map response did not contain JSON.");
    }
    const std::size_t jsonOffset = static_cast<std::size_t>(start - body.begin());
    std::size_t jsonLength = body.size() - jsonOffset;
    if (jsonOffset >= MapLengthSize)
    {
        const std::size_t framedLength = body[jsonOffset - 4] |
                                         (static_cast<std::size_t>(body[jsonOffset - 3]) << 8U) |
                                         (static_cast<std::size_t>(body[jsonOffset - 2]) << 16U) |
                                         (static_cast<std::size_t>(body[jsonOffset - 1]) << 24U);
        if (framedLength > 0 && jsonOffset + framedLength <= body.size())
        {
            jsonLength = framedLength;
        }
    }
    return ParseNetworkMap(std::string(start, start + static_cast<std::ptrdiff_t>(jsonLength)));
}

void LogMapResponse(const NetworkConfig& config, std::string_view source)
{
    Log(LogLevel::Info,
        "control",
        std::format("{}: address={} name={} peers={} derp={} dns={} cert-domains={}",
                    source,
                    config.SelfAddress,
                    config.SelfName,
                    config.Peers.size(),
                    config.DerpCode,
                    config.DnsResolver,
                    config.CertDomains.size()));
    for (const std::string& domain : config.CertDomains)
    {
        Log(LogLevel::Info, "control", "cert domain available: " + domain);
    }
    if (config.SelfIngressEnabled || config.SelfWireIngress || config.SelfPeerApi4Port != 0 ||
        config.SelfPeerApi6Port != 0)
    {
        Log(LogLevel::Info,
            "control",
            std::format(
                "{} self ingress metadata: version={} ingress={} wire-ingress={} peerapi4={} "
                "peerapi6={}",
                source,
                config.SelfClientVersion,
                config.SelfIngressEnabled ? 1 : 0,
                config.SelfWireIngress ? 1 : 0,
                config.SelfPeerApi4Port,
                config.SelfPeerApi6Port));
    }
}

} // namespace

class ControlClient::Impl
{
public:
    Impl(IByteStream& stream,
         const tailgate::crypto::Bytes32& machinePrivateKey,
         const tailgate::crypto::Bytes32& nodePublicKey,
         tailgate::control::client::HostInfo host)
        : Host(std::move(host)),
          NodePublic(nodePublicKey),
          NodeKey("nodekey:" + tailgate::crypto::BytesToHex(NodePublic.data(), NodePublic.size()))
    {
        const tailgate::crypto::Bytes32 ephemeralKey = tailgate::crypto::GeneratePrivateKey();
        tailgate::control::base::ControlHandshake handshake(machinePrivateKey, ephemeralKey);
        tailgate::control::base::ControlHandshakeResult result =
            handshake.Run(stream, tailgate::control::base::ControlHandshake::DefaultHost);
        Transport =
            std::make_unique<tailgate::control::base::NoiseTransport>(stream, std::move(result));
        Transport->Send(tailgate::control::base::BuildH2Preface(InitialH2WindowSize));
    }

    std::vector<std::uint8_t> Request(std::uint32_t streamId,
                                      const std::string& path,
                                      const std::vector<std::uint8_t>& body,
                                      bool waitForResponse)
    {
        std::vector<std::uint8_t> request = tailgate::control::base::BuildH2Headers(
            "POST",
            path,
            tailgate::control::base::ControlHandshake::DefaultHost,
            "application/json",
            {{"ts-lb", NodeKey}},
            streamId,
            false);
        std::vector<std::uint8_t> data = tailgate::control::base::BuildH2Data(body, streamId, true);
        request.insert(request.end(), data.begin(), data.end());
        Transport->Send(request);
        if (!waitForResponse)
        {
            return {};
        }

        std::vector<std::uint8_t> response;
        tailgate::control::base::H2Headers responseHeaders;
        std::optional<int> status;
        for (int attempt = 0; attempt < MaximumControlResponseFrames; ++attempt)
        {
            std::vector<std::uint8_t> plaintext = Transport->Receive();
            if (H2Buffer.empty() && !LooksLikeH2(plaintext))
            {
                continue;
            }
            H2Buffer.insert(H2Buffer.end(), plaintext.begin(), plaintext.end());
            for (const tailgate::control::base::H2Frame& frame :
                 tailgate::control::base::TakeCompleteH2Frames(H2Buffer))
            {
                if (frame.Type == tailgate::control::base::H2FrameType::Settings &&
                    (frame.Flags & H2EndOrAckFlag) == 0)
                {
                    Transport->Send(tailgate::control::base::BuildH2SettingsAck());
                }
                if (frame.Type == tailgate::control::base::H2FrameType::Headers)
                {
                    const auto headers = HeaderDecoder.Decode(frame.Payload);
                    if (headers && frame.StreamId == streamId)
                    {
                        responseHeaders.insert(headers->begin(), headers->end());
                        if (const auto decodedStatus = tailgate::control::base::H2Status(*headers))
                        {
                            status = decodedStatus;
                        }
                    }
                }
                if (frame.Type == tailgate::control::base::H2FrameType::Data &&
                    frame.StreamId == streamId)
                {
                    response.insert(response.end(), frame.Payload.begin(), frame.Payload.end());
                }
                if (frame.StreamId == streamId && (frame.Flags & H2EndOrAckFlag) != 0)
                {
                    if (status && *status >= 300)
                    {
                        throw ControlHttpError(path,
                                               *status,
                                               std::string(response.begin(), response.end()),
                                               ControlRetryAfterSeconds(responseHeaders));
                    }
                    return response;
                }
            }
        }
        throw std::runtime_error("Control response did not finish.");
    }

    void AnswerControlPing(const std::string& text)
    {
        const nlohmann::json map = nlohmann::json::parse(text, nullptr, false);
        if (map.is_discarded() || !map.is_object() || !map.contains("PingRequest"))
        {
            return;
        }

        const nlohmann::json& pingRequest = map.at("PingRequest");
        if (!pingRequest.is_object())
        {
            return;
        }
        const std::string url = pingRequest.value("URL", "");
        if (url.empty())
        {
            Log(LogLevel::Warning, "control", "ignoring control ping request without URL");
            return;
        }
        if (url == LastPingUrl)
        {
            return;
        }
        LastPingUrl = url;

        std::optional<std::vector<std::uint8_t>> response = BuildC2NResponse(pingRequest);
        if (!response)
        {
            Log(LogLevel::Debug,
                "control",
                std::format("ignoring unsupported control ping request types={}",
                            pingRequest.value("Types", "")));
            return;
        }

        const std::string path = UrlPathAndQuery(url);
        if (path.size() > MaximumSmallHpackLiteral)
        {
            Log(LogLevel::Warning, "control", "control ping response URL is too long");
            return;
        }
        const std::uint32_t streamId = NextStreamId;
        NextStreamId += 2;
        std::vector<std::uint8_t> request = tailgate::control::base::BuildH2Headers(
            "POST",
            path,
            tailgate::control::base::ControlHandshake::DefaultHost,
            "application/octet-stream",
            {{"ts-lb", NodeKey}},
            streamId,
            false);
        std::vector<std::uint8_t> data =
            tailgate::control::base::BuildH2Data(*response, streamId, true);
        request.insert(request.end(), data.begin(), data.end());
        Transport->Send(request);
        Log(LogLevel::Info,
            "control",
            std::format("answered c2n control ping path={} bytes={}", path, response->size()));
    }

    std::optional<NetworkConfig> TakeNetworkMapUpdate()
    {
        for (const tailgate::control::base::H2Frame& frame :
             tailgate::control::base::TakeCompleteH2Frames(H2Buffer))
        {
            if (frame.Type == tailgate::control::base::H2FrameType::Settings &&
                (frame.Flags & H2EndOrAckFlag) == 0)
            {
                Transport->Send(tailgate::control::base::BuildH2SettingsAck());
            }
            else if (frame.Type == tailgate::control::base::H2FrameType::Ping &&
                     (frame.Flags & H2EndOrAckFlag) == 0)
            {
                Transport->Send(tailgate::control::base::BuildH2PingAck(frame.Payload));
            }
            else if (frame.Type == tailgate::control::base::H2FrameType::GoAway)
            {
                throw std::runtime_error("Control server closed the HTTP/2 connection.");
            }
            else if (frame.Type == tailgate::control::base::H2FrameType::Data &&
                     frame.StreamId == MapStreamId)
            {
                MapBody.insert(MapBody.end(), frame.Payload.begin(), frame.Payload.end());
                if (!frame.Payload.empty())
                {
                    Transport->Send(tailgate::control::base::BuildH2WindowUpdate(
                        0, static_cast<std::uint32_t>(frame.Payload.size())));
                    Transport->Send(tailgate::control::base::BuildH2WindowUpdate(
                        frame.StreamId, static_cast<std::uint32_t>(frame.Payload.size())));
                }
            }
        }
        while (MapBody.size() >= MapLengthSize)
        {
            const std::size_t mapSize = MapBody[0] | (static_cast<std::size_t>(MapBody[1]) << 8U) |
                                        (static_cast<std::size_t>(MapBody[2]) << 16U) |
                                        (static_cast<std::size_t>(MapBody[3]) << 24U);
            if (mapSize > MaximumStreamingMapSize)
            {
                throw std::runtime_error("Streaming network map exceeds the protocol limit.");
            }
            if (MapBody.size() < MapLengthSize + mapSize)
            {
                return std::nullopt;
            }
            const std::string json(MapBody.begin() + static_cast<std::ptrdiff_t>(MapLengthSize),
                                   MapBody.begin() +
                                       static_cast<std::ptrdiff_t>(MapLengthSize + mapSize));
            MapBody.erase(MapBody.begin(),
                          MapBody.begin() + static_cast<std::ptrdiff_t>(MapLengthSize + mapSize));
            try
            {
                AnswerControlPing(json);
            }
            catch (const std::exception& error)
            {
                Log(LogLevel::Warning,
                    "control",
                    std::format("failed to answer control ping request: {}", error.what()));
            }
            if (std::optional<std::string> incremental = DescribeIncrementalNetworkMap(json))
            {
                Log(LogLevel::Debug, "control", *incremental);
                if (CurrentMap && ApplyNetworkMapUpdate(*CurrentMap, json))
                {
                    return CurrentMap;
                }
                continue;
            }
            try
            {
                NetworkConfig config = ParseNetworkMap(json);
                LogMapResponse(config, "streaming network map received");
                CurrentMap = config;
                return config;
            }
            catch (const std::exception& error)
            {
                Log(LogLevel::Debug,
                    "control",
                    std::format("consumed incremental network-map update: {}", error.what()));
            }
        }
        return std::nullopt;
    }

    tailgate::control::client::HostInfo Host;
    tailgate::crypto::Bytes32 NodePublic{};
    std::string NodeKey;
    tailgate::crypto::Bytes32 DiscoPrivate{};
    std::string DiscoKey;
    std::uint32_t NextStreamId = 1;
    std::uint32_t MapStreamId = 0;
    std::vector<std::uint8_t> H2Buffer;
    std::vector<std::uint8_t> MapBody;
    std::vector<tailgate::control::client::MapEndpoint> Endpoints;
    std::optional<NetworkConfig> CurrentMap;
    std::string LastPingUrl;
    tailgate::control::base::H2HeaderDecoder HeaderDecoder;
    std::unique_ptr<tailgate::control::base::NoiseTransport> Transport;
};

ControlClient::ControlClient(IByteStream& stream,
                             const tailgate::crypto::Bytes32& machinePrivateKey,
                             const tailgate::crypto::Bytes32& nodePrivateKey,
                             const tailgate::control::client::HostInfo& host)
    : Implementation(
          std::make_unique<Impl>(stream,
                                 machinePrivateKey,
                                 tailgate::crypto::X25519PublicFromPrivate(nodePrivateKey),
                                 host))
{
}

ControlClient::ControlClient(IByteStream& stream,
                             const tailgate::crypto::Bytes32& machinePrivateKey,
                             ExternalNodePublicKey nodePublicKey,
                             const tailgate::control::client::HostInfo& host)
    : Implementation(std::make_unique<Impl>(stream, machinePrivateKey, nodePublicKey.Value, host))
{
}

ControlClient::~ControlClient() = default;
ControlClient::ControlClient(ControlClient&&) noexcept = default;
ControlClient& ControlClient::operator=(ControlClient&&) noexcept = default;

RegistrationResult ControlClient::Register(const std::string& authKey,
                                           const std::string& followupUrl)
{
    const std::uint32_t streamId = Implementation->NextStreamId;
    Implementation->NextStreamId += 2;
    const std::vector<std::uint8_t> registration = Implementation->Request(
        streamId,
        "/machine/register",
        tailgate::control::client::BuildRegisterRequest(
            Implementation->NodeKey, authKey, followupUrl, Implementation->Host),
        true);
    const std::optional<tailgate::control::client::RegisterResponse> response =
        tailgate::control::client::ParseRegisterResponse(registration);
    if (!response)
    {
        throw std::runtime_error("Control returned an invalid node registration response.");
    }
    if (!response->Error.empty())
    {
        throw std::runtime_error(std::format("Node registration failed: {}.", response->Error));
    }
    if (response->NodeKeyExpired)
    {
        throw std::runtime_error("Control rejected the newly generated node key as expired.");
    }
    if (!response->AuthUrl.empty())
    {
        if (!tailgate::control::client::IsValidAuthorizationUrl(response->AuthUrl))
        {
            throw std::runtime_error("Control returned an unsafe node authorization URL.");
        }
        Log(LogLevel::Info, "control", "interactive node login is required");
        return RegistrationResult{
            .State = RegistrationState::LoginRequired,
            .AuthorizationUrl = response->AuthUrl,
            .AuthorizationCode = tailgate::control::client::AuthorizationCode(response->AuthUrl),
            .ApprovalUrl = {},
            .Network = std::nullopt};
    }
    Log(LogLevel::Info,
        "control",
        std::format("node registration accepted machine-authorized={}",
                    response->MachineAuthorized));
    if (std::all_of(Implementation->DiscoPrivate.begin(),
                    Implementation->DiscoPrivate.end(),
                    [](std::uint8_t byte)
                    {
                        return byte == 0;
                    }))
    {
        Implementation->DiscoPrivate = tailgate::crypto::GeneratePrivateKey();
    }
    const tailgate::crypto::Bytes32 discoPublic =
        tailgate::crypto::X25519PublicFromPrivate(Implementation->DiscoPrivate);
    Implementation->DiscoKey =
        "discokey:" + tailgate::crypto::BytesToHex(discoPublic.data(), discoPublic.size());
    NetworkConfig network = RequestNetworkMap();
    network.SelfMachineAuthorized = response->MachineAuthorized;
    return RegistrationResult{
        .State = response->MachineAuthorized ? RegistrationState::Complete
                                             : RegistrationState::MachineApprovalRequired,
        .AuthorizationUrl = {},
        .AuthorizationCode = {},
        .ApprovalUrl = response->MachineAuthorized
                           ? std::string{}
                           : tailgate::control::client::MachineApprovalUrl(network.SelfAddress),
        .Network = std::move(network)};
}

RegistrationResult ControlClient::RegisterUntilAuthorized(const std::string& authKey,
                                                          const RegistrationOptions& options)
{
    const auto registerWithRateLimitRetry =
        [this, &options](const std::string& key, const std::string& followupUrl)
    {
        while (true)
        {
            try
            {
                return Register(key, followupUrl);
            }
            catch (const ControlHttpError& error)
            {
                if (error.Status != 429)
                {
                    throw;
                }

                const std::chrono::milliseconds retryDelay =
                    RegistrationRateLimitRetryDelay(error.RetryAfterSeconds);
                Log(LogLevel::Warning,
                    "control",
                    std::format("node registration rate limited; retrying after {} milliseconds",
                                retryDelay.count()));
                bool shouldContinue = true;
                if (options.WaitForRetry)
                {
                    shouldContinue = options.WaitForRetry(retryDelay);
                }
                else
                {
                    std::this_thread::sleep_for(retryDelay);
                }
                if (!shouldContinue)
                {
                    throw std::runtime_error("Control registration was cancelled.");
                }
            }
        }
    };

    RegistrationResult registration =
        registerWithRateLimitRetry(authKey, options.InitialFollowupUrl);
    std::string followedAuthorizationUrl = options.InitialFollowupUrl;
    bool reauthorizationKeyUsed = false;
    while (registration.State != RegistrationState::Complete)
    {
        if (registration.State == RegistrationState::LoginRequired && authKey.empty() &&
            !options.ReauthorizationKey.empty() && !reauthorizationKeyUsed)
        {
            Log(LogLevel::Info,
                "control",
                "saved identity requires reauthorization; using the supplied auth key");
            reauthorizationKeyUsed = true;
            followedAuthorizationUrl.clear();
            registration = registerWithRateLimitRetry(options.ReauthorizationKey, {});
            continue;
        }
        if (options.StateChanged)
        {
            options.StateChanged(registration);
        }
        if (registration.State == RegistrationState::LoginRequired)
        {
            if (registration.AuthorizationUrl == followedAuthorizationUrl)
            {
                bool shouldContinue = true;
                if (options.WaitForRetry)
                {
                    shouldContinue = options.WaitForRetry(UnchangedAuthorizationUrlRetryDelay);
                }
                else
                {
                    std::this_thread::sleep_for(UnchangedAuthorizationUrlRetryDelay);
                }
                if (!shouldContinue)
                {
                    throw std::runtime_error("Control registration was cancelled.");
                }
            }
            followedAuthorizationUrl = registration.AuthorizationUrl;
            registration = registerWithRateLimitRetry({}, followedAuthorizationUrl);
            continue;
        }
        if (!registration.Network)
        {
            throw std::runtime_error("Machine approval requires a network map.");
        }
        SetPreferredDerp(registration.Network->DerpRegion);
        registration.NetworkMapStreaming = true;
        while (!registration.Network->SelfMachineAuthorized)
        {
            registration.Network = WaitForNetworkMap();
        }
        registration.State = RegistrationState::Complete;
        registration.ApprovalUrl.clear();
    }
    return registration;
}

NetworkConfig ControlClient::RequestNetworkMap()
{
    std::vector<std::uint8_t> body;
    std::chrono::milliseconds retryDelay = InitialMapRetryDelay;
    for (int attempt = 1; attempt <= MaximumInitialMapAttempts; ++attempt)
    {
        const std::uint32_t streamId = Implementation->NextStreamId;
        Implementation->NextStreamId += 2;
        try
        {
            body = Implementation->Request(
                streamId,
                "/machine/map",
                tailgate::control::client::BuildReadOnlyMapRequest(
                    Implementation->NodeKey, Implementation->DiscoKey, Implementation->Host),
                true);
            break;
        }
        catch (const ControlHttpError& error)
        {
            if (attempt == MaximumInitialMapAttempts ||
                !tailgate::control::client::IsRetryableInitialMapError(error.Status, error.Body))
            {
                throw;
            }
            Log(LogLevel::Warning,
                "control",
                "new node is not visible to the map service yet; retrying initial map");
            std::this_thread::sleep_for(retryDelay);
            retryDelay = std::min(retryDelay * 2, MaximumMapRetryDelay);
        }
    }

    NetworkConfig config = ParseMapResponseBody(body);
    LogMapResponse(config, "network map received");
    Implementation->CurrentMap = config;
    return config;
}

FeatureEnablement ControlClient::QueryFeature(const std::string& feature)
{
    const std::vector<std::uint8_t> body = Implementation->Request(
        Implementation->NextStreamId,
        "/machine/feature/query",
        tailgate::control::client::BuildQueryFeatureRequest(Implementation->NodeKey, feature),
        true);
    Implementation->NextStreamId += 2;

    const nlohmann::json json = nlohmann::json::parse(body, nullptr, false);
    if (json.is_discarded() || !json.is_object())
    {
        throw std::runtime_error("Control feature query response did not contain JSON.");
    }
    return FeatureEnablement{.Complete = json.value("Complete", false),
                             .ShouldWait = json.value("ShouldWait", false),
                             .Text = json.value("Text", ""),
                             .Url = json.value("URL", "")};
}

void ControlClient::SetDnsTxt(const std::string& name, const std::string& value)
{
    if (name.empty() || value.empty())
    {
        throw std::invalid_argument("DNS TXT name and value must not be empty.");
    }
    (void)Implementation->Request(
        Implementation->NextStreamId,
        "/machine/set-dns",
        tailgate::control::client::BuildSetDnsRequest(Implementation->NodeKey, name, value),
        true);
    Implementation->NextStreamId += 2;
}

void ControlClient::UpdateHostInfo(int preferredDerp)
{
    const std::vector<std::uint8_t> body =
        tailgate::control::client::BuildMapRequest(Implementation->NodeKey,
                                                   Implementation->DiscoKey,
                                                   Implementation->Host,
                                                   preferredDerp,
                                                   false,
                                                   true,
                                                   Implementation->Endpoints,
                                                   true);
    Log(LogLevel::Info,
        "control",
        std::format("sending hostinfo update: ingress={} peerapi-services={} endpoints={} "
                    "preferred-derp={}",
                    Implementation->Host.IngressEnabled ? 1 : 0,
                    Implementation->Host.Services.size(),
                    Implementation->Endpoints.size(),
                    preferredDerp));
    const std::vector<std::uint8_t> response =
        Implementation->Request(Implementation->NextStreamId, "/machine/map", body, true);
    Implementation->NextStreamId += 2;
    Log(LogLevel::Info,
        "control",
        std::format("hostinfo update accepted response-bytes={}", response.size()));
}

void ControlClient::SetDiscoPrivateKey(const tailgate::crypto::Bytes32& privateKey)
{
    Implementation->DiscoPrivate = privateKey;
    const tailgate::crypto::Bytes32 publicKey =
        tailgate::crypto::X25519PublicFromPrivate(privateKey);
    Implementation->DiscoKey =
        "discokey:" + tailgate::crypto::BytesToHex(publicKey.data(), publicKey.size());
}

void ControlClient::SetEndpoints(std::vector<tailgate::control::client::MapEndpoint> endpoints)
{
    Implementation->Endpoints = std::move(endpoints);
}

void ControlClient::SetPreferredDerp(int region)
{
    (void)Implementation->Request(
        Implementation->NextStreamId,
        "/machine/map",
        tailgate::control::client::BuildMapRequest(Implementation->NodeKey,
                                                   Implementation->DiscoKey,
                                                   Implementation->Host,
                                                   region,
                                                   true,
                                                   false,
                                                   Implementation->Endpoints),
        false);
    Implementation->MapStreamId = Implementation->NextStreamId;
    Implementation->NextStreamId += 2;
    Log(LogLevel::Info,
        "control",
        std::format("streaming network map started with preferred DERP {} ingress={} "
                    "peerapi-services={}",
                    region,
                    Implementation->Host.IngressEnabled ? 1 : 0,
                    Implementation->Host.Services.size()));
}

std::optional<NetworkConfig> ControlClient::PollNetworkMap()
{
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
    return Implementation->TakeNetworkMapUpdate();
}

NetworkConfig ControlClient::WaitForNetworkMap()
{
    Implementation->Transport->Flush();
    while (true)
    {
        if (std::optional<NetworkConfig> update = Implementation->TakeNetworkMapUpdate())
        {
            return std::move(*update);
        }
        std::vector<std::uint8_t> plaintext = Implementation->Transport->Receive();
        Implementation->H2Buffer.insert(
            Implementation->H2Buffer.end(), plaintext.begin(), plaintext.end());
    }
}

void ControlClient::Logout()
{
    (void)Implementation->Request(Implementation->NextStreamId,
                                  "/machine/register",
                                  tailgate::control::client::BuildLogoutRequest(
                                      Implementation->NodeKey, Implementation->Host),
                                  true);
    Implementation->NextStreamId += 2;
    Log(LogLevel::Info, "control", "node expiry accepted");
}

const tailgate::crypto::Bytes32& ControlClient::NodePublicKey() const
{
    return Implementation->NodePublic;
}

const tailgate::crypto::Bytes32& ControlClient::DiscoPrivateKey() const
{
    return Implementation->DiscoPrivate;
}

} // namespace tailgate::control::client
