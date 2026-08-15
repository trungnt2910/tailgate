#include "tailgate/hosted/Protocol.h"

#include <array>
#include <cctype>
#include <cstring>
#include <format>
#include <limits>
#include <stdexcept>

#include <nlohmann/json.hpp>
#include <sodium.h>

namespace tailgate::hosted
{

using tailgate::base::IByteStream;

namespace
{

constexpr std::array<std::uint8_t, 4> Magic = {'T', 'G', 'R', '1'};
constexpr std::size_t HeaderSize = 12;
constexpr std::size_t MaximumPayloadSize = 1024U * 1024U;
constexpr std::size_t CompactThreshold = 64U * 1024U;
constexpr std::size_t MaximumHttpHeaderSize = 16U * 1024U;
constexpr std::size_t MaximumHostnameSize = 253;
constexpr std::size_t MaximumOperatingSystemSize = 64;
constexpr std::size_t MaximumOperatingSystemVersionSize = 256;

void Append16(std::vector<std::uint8_t>& output, std::uint16_t value)
{
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void Append32(std::vector<std::uint8_t>& output, std::uint32_t value)
{
    output.push_back(static_cast<std::uint8_t>(value >> 24U));
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void Append64(std::vector<std::uint8_t>& output, std::uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8)
    {
        output.push_back(static_cast<std::uint8_t>(value >> static_cast<unsigned>(shift)));
    }
}

std::uint16_t Read16(const std::uint8_t* data)
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8U) | data[1]);
}

std::uint32_t Read32(const std::uint8_t* data)
{
    return (static_cast<std::uint32_t>(data[0]) << 24U) |
           (static_cast<std::uint32_t>(data[1]) << 16U) |
           (static_cast<std::uint32_t>(data[2]) << 8U) | static_cast<std::uint32_t>(data[3]);
}

std::uint64_t Read64(const std::uint8_t* data)
{
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < sizeof(value); ++index)
    {
        value = (value << 8U) | data[index];
    }
    return value;
}

std::vector<std::uint8_t> JsonBytes(const nlohmann::json& value)
{
    const std::string text = value.dump();
    return {text.begin(), text.end()};
}

nlohmann::json ParseJson(const std::vector<std::uint8_t>& payload)
{
    if (payload.empty())
    {
        throw std::runtime_error("Relay JSON payload is empty.");
    }
    return nlohmann::json::parse(payload.begin(), payload.end());
}

bool IsKnownType(std::uint16_t value)
{
    return value >= static_cast<std::uint16_t>(MessageType::Authenticate) &&
           value <= static_cast<std::uint16_t>(MessageType::TailnetDnsResponse);
}

tailgate::crypto::Bytes32
DecodeBytes32(const nlohmann::json& value, const char* name, const char* error)
{
    const std::vector<std::uint8_t> bytes =
        tailgate::crypto::HexToBytes(value.at(name).get<std::string>());
    if (bytes.size() != tailgate::crypto::Bytes32{}.size())
    {
        throw std::runtime_error(error);
    }
    tailgate::crypto::Bytes32 result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

std::string EncodeBytes32(const tailgate::crypto::Bytes32& value)
{
    return tailgate::crypto::BytesToHex(value.data(), value.size());
}

tailgate::crypto::Bytes32 CreateProof(const char* context,
                                      const tailgate::crypto::Bytes32& privateKey,
                                      const tailgate::crypto::Bytes32& publicKey,
                                      const tailgate::crypto::Bytes32& serverNonce,
                                      const tailgate::crypto::Bytes32& clientNonce,
                                      const std::string& profileId)
{
    const tailgate::crypto::Bytes32 shared = tailgate::crypto::X25519Shared(privateKey, publicKey);
    std::vector<std::uint8_t> message(context, context + std::strlen(context));
    message.insert(message.end(), serverNonce.begin(), serverNonce.end());
    message.insert(message.end(), clientNonce.begin(), clientNonce.end());
    message.insert(message.end(), profileId.begin(), profileId.end());
    return tailgate::crypto::HmacBlake2s256(
        shared.data(), shared.size(), message.data(), message.size());
}

struct HttpHeaders
{
    std::string Value;
    std::vector<std::uint8_t> TrailingData;
};

HttpHeaders ReadHttpHeaders(IByteStream& stream)
{
    std::vector<std::uint8_t> input;
    constexpr std::string_view terminator = "\r\n\r\n";
    while (true)
    {
        const std::vector<std::uint8_t> part = stream.ReadSome(1024);
        if (part.empty())
        {
            throw std::runtime_error("Relay HTTP connection closed during headers.");
        }
        input.insert(input.end(), part.begin(), part.end());
        const auto end =
            std::search(input.begin(), input.end(), terminator.begin(), terminator.end());
        if (end != input.end())
        {
            const auto body = end + static_cast<std::ptrdiff_t>(terminator.size());
            return HttpHeaders{
                .Value = std::string(input.begin(), body),
                .TrailingData = std::vector<std::uint8_t>(body, input.end()),
            };
        }
        if (input.size() > MaximumHttpHeaderSize)
        {
            throw std::runtime_error("Relay HTTP headers exceed the limit.");
        }
    }
}

std::vector<std::uint8_t> Bytes(const std::string& value)
{
    return {value.begin(), value.end()};
}

} // namespace

std::vector<std::uint8_t> Encode(const Frame& frame)
{
    if (frame.Payload.size() > MaximumPayloadSize ||
        frame.Payload.size() > std::numeric_limits<std::uint32_t>::max())
    {
        throw std::runtime_error("Relay frame payload is too large.");
    }
    const auto type = static_cast<std::uint16_t>(frame.Type);
    if (!IsKnownType(type))
    {
        throw std::runtime_error("Relay frame has an unknown message type.");
    }

    std::vector<std::uint8_t> output;
    output.reserve(HeaderSize + frame.Payload.size());
    output.insert(output.end(), Magic.begin(), Magic.end());
    Append16(output, type);
    Append16(output, 0);
    Append32(output, static_cast<std::uint32_t>(frame.Payload.size()));
    output.insert(output.end(), frame.Payload.begin(), frame.Payload.end());
    return output;
}

std::vector<std::uint8_t> EncodeAuthentication(const Authentication& authentication)
{
    return JsonBytes({
        {"Tailnet", authentication.Tailnet},
        {"NodeId", authentication.NodeId},
        {"Hostname", authentication.Hostname},
        {"OS", authentication.OperatingSystem},
        {"OSVersion", authentication.OperatingSystemVersion},
        {"NodePublicKey", EncodeBytes32(authentication.NodePublicKey)},
        {"ClientNonce", EncodeBytes32(authentication.ClientNonce)},
        {"ClientProof", EncodeBytes32(authentication.ClientProof)},
    });
}

Authentication DecodeAuthentication(const std::vector<std::uint8_t>& payload)
{
    const nlohmann::json value = ParseJson(payload);
    Authentication result;
    result.Tailnet = value.at("Tailnet").get<std::string>();
    result.NodeId = value.at("NodeId").get<std::uint64_t>();
    result.Hostname = value.at("Hostname").get<std::string>();
    result.OperatingSystem = value.at("OS").get<std::string>();
    result.OperatingSystemVersion = value.at("OSVersion").get<std::string>();
    result.NodePublicKey = DecodeBytes32(
        value, "NodePublicKey", "Relay authentication has an invalid node public key.");
    result.ClientNonce =
        DecodeBytes32(value, "ClientNonce", "Relay authentication has an invalid client nonce.");
    result.ClientProof =
        DecodeBytes32(value, "ClientProof", "Relay authentication has an invalid client proof.");
    if (result.Tailnet.empty() || result.NodeId == 0 || result.Hostname.empty() ||
        result.Hostname.size() > MaximumHostnameSize ||
        result.OperatingSystem.size() > MaximumOperatingSystemSize ||
        result.OperatingSystemVersion.size() > MaximumOperatingSystemVersionSize)
    {
        throw std::runtime_error("Relay authentication is missing required fields.");
    }
    return result;
}

std::vector<std::uint8_t> EncodeChallenge(const Challenge& challenge)
{
    return JsonBytes({{"RelayPublicKey", EncodeBytes32(challenge.RelayPublicKey)},
                      {"ServerNonce", EncodeBytes32(challenge.ServerNonce)}});
}

Challenge DecodeChallenge(const std::vector<std::uint8_t>& payload)
{
    const nlohmann::json value = ParseJson(payload);
    return Challenge{.RelayPublicKey = DecodeBytes32(
                         value, "RelayPublicKey", "Relay challenge has an invalid public key."),
                     .ServerNonce = DecodeBytes32(
                         value, "ServerNonce", "Relay challenge has an invalid nonce.")};
}

std::vector<std::uint8_t> EncodeSession(const Session& session)
{
    return JsonBytes({
        {"Tailnet", session.Tailnet},
        {"RelayHostName", session.RelayHostName},
        {"RelayHostAddress", session.RelayHostAddress},
        {"ServerProof", EncodeBytes32(session.ServerProof)},
    });
}

Session DecodeSession(const std::vector<std::uint8_t>& payload)
{
    const nlohmann::json value = ParseJson(payload);
    Session result;
    result.Tailnet = value.at("Tailnet").get<std::string>();
    result.RelayHostName = value.value("RelayHostName", "");
    result.RelayHostAddress = value.value("RelayHostAddress", "");
    result.ServerProof =
        DecodeBytes32(value, "ServerProof", "Relay session has an invalid server proof.");
    if (result.Tailnet.empty())
    {
        throw std::runtime_error("Relay session is missing required fields.");
    }
    return result;
}

tailgate::crypto::Bytes32 CreateClientProof(const tailgate::crypto::Bytes32& clientPrivateKey,
                                            const tailgate::crypto::Bytes32& relayPublicKey,
                                            const tailgate::crypto::Bytes32& serverNonce,
                                            const tailgate::crypto::Bytes32& clientNonce)
{
    return CreateProof(
        "tailgate-relay-client-v1", clientPrivateKey, relayPublicKey, serverNonce, clientNonce, {});
}

tailgate::crypto::Bytes32 CreateServerProof(const tailgate::crypto::Bytes32& relayPrivateKey,
                                            const tailgate::crypto::Bytes32& clientPublicKey,
                                            const tailgate::crypto::Bytes32& serverNonce,
                                            const tailgate::crypto::Bytes32& clientNonce)
{
    return CreateProof(
        "tailgate-relay-server-v1", relayPrivateKey, clientPublicKey, serverNonce, clientNonce, {});
}

bool ProofMatches(const tailgate::crypto::Bytes32& expected,
                  const tailgate::crypto::Bytes32& actual)
{
    return sodium_memcmp(expected.data(), actual.data(), expected.size()) == 0;
}

std::vector<std::uint8_t> EncodeRejection(const Rejection& rejection)
{
    return JsonBytes({{"Reason", rejection.Reason}});
}

Rejection DecodeRejection(const std::vector<std::uint8_t>& payload)
{
    Rejection result;
    result.Reason = ParseJson(payload).at("Reason").get<std::string>();
    if (result.Reason.empty())
    {
        throw std::runtime_error("Relay rejection reason is empty.");
    }
    return result;
}

std::vector<std::uint8_t> EncodePeerPacket(const PeerPacket& packet)
{
    constexpr std::uint8_t ControlFlag = 1U << 0U;
    constexpr std::uint8_t DiscoFlag = 1U << 1U;
    constexpr std::uint8_t EndpointFlag = 1U << 2U;
    if (packet.Payload.empty())
    {
        throw std::invalid_argument("Relay peer packet has no payload.");
    }
    std::vector<std::uint8_t> result(packet.Peer.begin(), packet.Peer.end());
    const bool hasEndpoint = packet.EndpointAddress != 0 && packet.EndpointPort != 0;
    result.push_back((packet.Control ? ControlFlag : 0U) | (packet.Disco ? DiscoFlag : 0U) |
                     (hasEndpoint ? EndpointFlag : 0U));
    if (hasEndpoint)
    {
        Append32(result, packet.EndpointAddress);
        Append16(result, packet.EndpointPort);
    }
    result.insert(result.end(), packet.Payload.begin(), packet.Payload.end());
    return result;
}

PeerPacket DecodePeerPacket(const std::vector<std::uint8_t>& payload)
{
    constexpr std::uint8_t ControlFlag = 1U << 0U;
    constexpr std::uint8_t DiscoFlag = 1U << 1U;
    constexpr std::uint8_t EndpointFlag = 1U << 2U;
    constexpr std::size_t FlagsSize = 1;
    if (payload.size() <= tailgate::crypto::Bytes32{}.size() + FlagsSize)
    {
        throw std::runtime_error("Relay peer packet is truncated.");
    }
    PeerPacket result;
    std::copy_n(payload.begin(), result.Peer.size(), result.Peer.begin());
    const std::uint8_t flags = payload[result.Peer.size()];
    result.Control = (flags & ControlFlag) != 0;
    result.Disco = (flags & DiscoFlag) != 0;
    std::size_t dataOffset = result.Peer.size() + FlagsSize;
    if ((flags & EndpointFlag) != 0)
    {
        constexpr std::size_t EndpointSize = sizeof(std::uint32_t) + sizeof(std::uint16_t);
        if (payload.size() <= dataOffset + EndpointSize)
        {
            throw std::runtime_error("Relay peer packet endpoint is truncated.");
        }
        result.EndpointAddress = Read32(payload.data() + dataOffset);
        result.EndpointPort = Read16(payload.data() + dataOffset + sizeof(std::uint32_t));
        dataOffset += EndpointSize;
    }
    result.Payload.assign(payload.begin() + static_cast<std::ptrdiff_t>(dataOffset), payload.end());
    return result;
}

std::vector<std::uint8_t> EncodeDerpChallenge(const DerpAuthenticationChallenge& challenge)
{
    std::vector<std::uint8_t> result;
    result.reserve(sizeof(challenge.RequestId) + challenge.ServerKey.size());
    Append64(result, challenge.RequestId);
    result.insert(result.end(), challenge.ServerKey.begin(), challenge.ServerKey.end());
    return result;
}

DerpAuthenticationChallenge DecodeDerpChallenge(const std::vector<std::uint8_t>& payload)
{
    if (payload.size() != sizeof(std::uint64_t) + tailgate::crypto::Bytes32{}.size())
    {
        throw std::runtime_error("Relay DERP challenge has an invalid size.");
    }
    DerpAuthenticationChallenge result;
    result.RequestId = Read64(payload.data());
    std::copy(payload.begin() + static_cast<std::ptrdiff_t>(sizeof(result.RequestId)),
              payload.end(),
              result.ServerKey.begin());
    return result;
}

std::vector<std::uint8_t> EncodeDerpResponse(const DerpAuthenticationResponse& response)
{
    if (response.ClientInfo.empty())
    {
        throw std::invalid_argument("Relay DERP response has no ClientInfo envelope.");
    }
    std::vector<std::uint8_t> result;
    result.reserve(sizeof(response.RequestId) + response.ClientInfo.size());
    Append64(result, response.RequestId);
    result.insert(result.end(), response.ClientInfo.begin(), response.ClientInfo.end());
    return result;
}

DerpAuthenticationResponse DecodeDerpResponse(const std::vector<std::uint8_t>& payload)
{
    if (payload.size() <= sizeof(std::uint64_t))
    {
        throw std::runtime_error("Relay DERP response is truncated.");
    }
    DerpAuthenticationResponse result;
    result.RequestId = Read64(payload.data());
    result.ClientInfo.assign(
        payload.begin() + static_cast<std::ptrdiff_t>(sizeof(result.RequestId)), payload.end());
    return result;
}

std::vector<std::uint8_t> EncodeNetworkConfig(const tailgate::types::netmap::NetworkConfig& config)
{
    nlohmann::json peers = nlohmann::json::array();
    for (const tailgate::types::netmap::PeerConfig& peer : config.Peers)
    {
        nlohmann::json prefixes = nlohmann::json::array();
        for (const tailgate::net::packet::Ipv4Prefix& prefix : peer.AllowedPrefixes)
        {
            prefixes.push_back({{"Network", prefix.Network}, {"Bits", prefix.PrefixLength}});
        }
        peers.push_back({
            {"NodeId", peer.NodeId},
            {"OwnerId", peer.OwnerId},
            {"Name", peer.Name},
            {"Address", peer.Address},
            {"Addresses", peer.Addresses},
            {"Key", peer.Key},
            {"DiscoKey", peer.DiscoKey},
            {"Endpoints", peer.Endpoints},
            {"AllowedPrefixes", std::move(prefixes)},
            {"DerpRegion", peer.DerpRegion},
            {"DerpCode", peer.DerpCode},
            {"DerpHost", peer.DerpHost},
            {"OS", peer.OperatingSystem},
            {"ClientVersion", peer.ClientVersion},
            {"Owner", peer.Owner},
            {"Online", peer.Online},
            {"ExitNodeOption", peer.ExitNodeOption},
        });
    }
    nlohmann::json dnsRoutes = nlohmann::json::array();
    for (const tailgate::types::netmap::NetworkConfig::DnsRoute& route : config.DnsRoutes)
    {
        dnsRoutes.push_back({{"Suffix", route.Suffix}, {"Resolvers", route.Resolvers}});
    }
    nlohmann::json userProfiles = nlohmann::json::array();
    for (const tailgate::types::netmap::UserProfile& profile : config.UserProfiles)
    {
        userProfiles.push_back({{"Id", profile.Id},
                                {"LoginName", profile.LoginName},
                                {"DisplayName", profile.DisplayName},
                                {"ProfilePicUrl", profile.ProfilePicUrl}});
    }
    return JsonBytes({
        {"SelfNodeId", config.SelfNodeId},
        {"SelfKey", config.SelfKey},
        {"SelfAddress", config.SelfAddress},
        {"SelfAddresses", config.SelfAddresses},
        {"SelfName", config.SelfName},
        {"Domain", config.Domain},
        {"MagicDnsDomain", config.MagicDnsDomain},
        {"TailnetDisplayName", config.TailnetDisplayName},
        {"DnsResolver", config.DnsResolver},
        {"DnsDomains", config.DnsDomains},
        {"DnsDefaultResolvers", config.DnsDefaultResolvers},
        {"DnsRoutes", std::move(dnsRoutes)},
        {"DerpRegion", config.DerpRegion},
        {"DerpHost", config.DerpHost},
        {"DerpCode", config.DerpCode},
        {"UserProfiles", std::move(userProfiles)},
        {"Peers", std::move(peers)},
    });
}

tailgate::types::netmap::NetworkConfig DecodeNetworkConfig(const std::vector<std::uint8_t>& payload)
{
    const nlohmann::json value = ParseJson(payload);
    tailgate::types::netmap::NetworkConfig config;
    config.SelfNodeId = value.value("SelfNodeId", std::uint64_t{0});
    config.SelfKey = value.value("SelfKey", "");
    config.SelfAddress = value.at("SelfAddress").get<std::string>();
    config.SelfAddresses = value.value("SelfAddresses", std::vector<std::string>{});
    config.SelfName = value.at("SelfName").get<std::string>();
    config.Domain = value.at("Domain").get<std::string>();
    config.MagicDnsDomain = value.value("MagicDnsDomain", "");
    config.TailnetDisplayName = value.value("TailnetDisplayName", "");
    config.DnsResolver = value.value("DnsResolver", "");
    config.DnsDomains = value.value("DnsDomains", std::vector<std::string>{});
    config.DnsDefaultResolvers = value.value("DnsDefaultResolvers", std::vector<std::string>{});
    config.DerpRegion = value.value("DerpRegion", 0);
    config.DerpHost = value.value("DerpHost", "");
    config.DerpCode = value.value("DerpCode", "");
    for (const nlohmann::json& source : value.value("UserProfiles", nlohmann::json::array()))
    {
        config.UserProfiles.push_back(tailgate::types::netmap::UserProfile{
            .Id = source.value("Id", std::uint64_t{0}),
            .LoginName = source.value("LoginName", ""),
            .DisplayName = source.value("DisplayName", ""),
            .ProfilePicUrl = source.value("ProfilePicUrl", "")});
    }
    for (const nlohmann::json& route : value.value("DnsRoutes", nlohmann::json::array()))
    {
        config.DnsRoutes.push_back(
            {route.value("Suffix", ""), route.value("Resolvers", std::vector<std::string>{})});
    }
    for (const nlohmann::json& source : value.at("Peers"))
    {
        tailgate::types::netmap::PeerConfig peer;
        peer.NodeId = source.value("NodeId", std::uint64_t{0});
        peer.OwnerId = source.value("OwnerId", std::uint64_t{0});
        peer.Name = source.value("Name", "");
        peer.Address = source.value("Address", "");
        peer.Addresses = source.value("Addresses", std::vector<std::string>{});
        peer.Key = source.value("Key", "");
        peer.DiscoKey = source.value("DiscoKey", "");
        peer.Endpoints = source.value("Endpoints", std::vector<std::string>{});
        peer.DerpRegion = source.value("DerpRegion", 0);
        peer.DerpCode = source.value("DerpCode", "");
        peer.DerpHost = source.value("DerpHost", "");
        peer.OperatingSystem = source.value("OS", "");
        peer.ClientVersion = source.value("ClientVersion", "");
        peer.Owner = source.value("Owner", "");
        peer.Online = source.value("Online", false);
        peer.ExitNodeOption = source.value("ExitNodeOption", false);
        for (const nlohmann::json& prefix :
             source.value("AllowedPrefixes", nlohmann::json::array()))
        {
            peer.AllowedPrefixes.push_back(
                {prefix.value("Network", std::uint32_t{0}), prefix.value("Bits", std::uint8_t{0})});
        }
        config.Peers.push_back(std::move(peer));
    }
    if (config.SelfNodeId == 0 || config.SelfKey.empty() || config.SelfAddress.empty() ||
        config.Domain.empty())
    {
        throw std::runtime_error("Relay network configuration is incomplete.");
    }
    return config;
}

void AcceptHttpUpgrade(IByteStream& stream)
{
    const std::string request = ReadHttpHeaders(stream).Value;
    const bool validRequest = request.rfind("POST /tailgate HTTP/1.1\r\n", 0) == 0;
    const bool validUpgrade = request.find("\r\nUpgrade: tailgate\r\n") != std::string::npos ||
                              request.find("\r\nupgrade: tailgate\r\n") != std::string::npos;
    if (!validRequest || !validUpgrade)
    {
        stream.WriteAll(Bytes("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"));
        throw std::runtime_error("Relay HTTP upgrade request is invalid.");
    }
    stream.WriteAll(Bytes(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tailgate\r\n\r\n"));
}

std::vector<std::uint8_t> RequestHttpUpgrade(IByteStream& stream, const std::string& host)
{
    if (host.empty())
    {
        throw std::invalid_argument("Relay HTTP host is empty.");
    }
    stream.WriteAll(Bytes(std::format("POST /tailgate HTTP/1.1\r\nHost: {}\r\n"
                                      "Connection: Upgrade\r\nUpgrade: tailgate\r\n\r\n",
                                      host)));
    HttpHeaders response = ReadHttpHeaders(stream);
    if (response.Value.rfind("HTTP/1.1 101 ", 0) != 0)
    {
        throw std::runtime_error("Relay server rejected HTTP upgrade.");
    }
    return std::move(response.TrailingData);
}

void Decoder::Feed(const std::uint8_t* data, std::size_t size)
{
    if (size == 0)
    {
        return;
    }
    if (data == nullptr)
    {
        throw std::invalid_argument("Relay decoder input is null.");
    }
    if (m_offset != 0 && (m_offset >= CompactThreshold || m_offset == m_buffer.size()))
    {
        m_buffer.erase(m_buffer.begin(), m_buffer.begin() + static_cast<std::ptrdiff_t>(m_offset));
        m_offset = 0;
    }
    if (size > HeaderSize + MaximumPayloadSize ||
        m_buffer.size() - m_offset > HeaderSize + MaximumPayloadSize - size)
    {
        throw std::runtime_error("Relay decoder buffer limit exceeded.");
    }
    m_buffer.insert(m_buffer.end(), data, data + size);
}

void Decoder::Feed(const std::vector<std::uint8_t>& data)
{
    Feed(data.data(), data.size());
}

std::optional<Frame> Decoder::Next()
{
    const std::size_t available = m_buffer.size() - m_offset;
    if (available < HeaderSize)
    {
        return std::nullopt;
    }
    const std::uint8_t* header = m_buffer.data() + m_offset;
    if (!std::equal(Magic.begin(), Magic.end(), header))
    {
        throw std::runtime_error("Relay frame has invalid magic.");
    }
    const std::uint16_t type = Read16(header + 4);
    if (!IsKnownType(type))
    {
        throw std::runtime_error("Relay frame has an unknown message type.");
    }
    if (Read16(header + 6) != 0)
    {
        throw std::runtime_error("Relay frame uses unsupported flags.");
    }
    const std::uint32_t payloadSize = Read32(header + 8);
    if (payloadSize > MaximumPayloadSize)
    {
        throw std::runtime_error("Relay frame payload exceeds the limit.");
    }
    if (available < HeaderSize + payloadSize)
    {
        return std::nullopt;
    }

    Frame result;
    result.Type = static_cast<MessageType>(type);
    const std::uint8_t* payload = header + HeaderSize;
    result.Payload.assign(payload, payload + payloadSize);
    m_offset += HeaderSize + payloadSize;
    return result;
}

std::size_t Decoder::BufferedBytes() const
{
    return m_buffer.size() - m_offset;
}

void WriteFrame(IByteStream& stream, const Frame& frame)
{
    stream.WriteAll(Encode(frame));
}

Frame ReadFrame(IByteStream& stream, Decoder& decoder)
{
    while (true)
    {
        if (std::optional<Frame> frame = decoder.Next())
        {
            return std::move(*frame);
        }
        const std::vector<std::uint8_t> input = stream.ReadSome(16U * 1024U);
        if (input.empty())
        {
            throw std::runtime_error("Relay connection closed while reading a frame.");
        }
        decoder.Feed(input);
    }
}

} // namespace tailgate::hosted
