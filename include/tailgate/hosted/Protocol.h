#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <tailgate/base/ByteStream.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/net/Endpoint.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::hosted
{

enum class MessageType : std::uint16_t
{
    Authenticate = 1,
    Authenticated = 2,
    Rejected = 3,
    NetworkMap = 4,
    ClientPacket = 5,
    ServerPacket = 6,
    Status = 7,
    Ping = 8,
    Pong = 9,
    Heartbeat = 10,
    Shutdown = 11,
    Error = 12,
    ServerChallenge = 13,
    DerpChallenge = 14,
    DerpResponse = 15,
    TailnetDnsQuery = 16,
    TailnetDnsResponse = 17,
    PeerEndpoint = 18,
    DataPathReady = 19,
    ServerEndpointCandidates = 20,
};

class Frame
{
public:
    static constexpr std::size_t HeaderSize = 12;
    static constexpr std::size_t MaximumPayloadSize = 1024U * 1024U;
    static constexpr std::size_t MaximumEncodedSize = HeaderSize + MaximumPayloadSize;

    Frame(MessageType type, std::vector<std::uint8_t> payload)
        : m_type(type), m_payload(std::move(payload))
    {
    }

    [[nodiscard]] std::vector<std::uint8_t> Encode() const;
    [[nodiscard]] static std::vector<std::uint8_t> EncodeAll(const std::vector<Frame>& frames);
    void Write(tailgate::base::ByteStream& stream) const;

    [[nodiscard]] MessageType Type() const noexcept
    {
        return m_type;
    }

    [[nodiscard]] const std::vector<std::uint8_t>& Payload() const noexcept
    {
        return m_payload;
    }

private:
    MessageType m_type;
    std::vector<std::uint8_t> m_payload;
};

class Authentication
{
public:
    Authentication(std::string tailnet,
                   std::uint64_t nodeId,
                   std::string hostname,
                   std::string operatingSystem,
                   std::string operatingSystemVersion,
                   tailgate::crypto::Bytes32 nodePublicKey,
                   tailgate::crypto::Bytes32 clientNonce,
                   tailgate::crypto::Bytes32 clientProof)
        : m_tailnet(std::move(tailnet)),
          m_nodeId(nodeId),
          m_hostname(std::move(hostname)),
          m_operatingSystem(std::move(operatingSystem)),
          m_operatingSystemVersion(std::move(operatingSystemVersion)),
          m_nodePublicKey(nodePublicKey),
          m_clientNonce(clientNonce),
          m_clientProof(clientProof)
    {
    }

    [[nodiscard]] const std::string& Tailnet() const noexcept
    {
        return m_tailnet;
    }

    [[nodiscard]] std::uint64_t NodeId() const noexcept
    {
        return m_nodeId;
    }

    [[nodiscard]] const std::string& Hostname() const noexcept
    {
        return m_hostname;
    }

    [[nodiscard]] const std::string& OperatingSystem() const noexcept
    {
        return m_operatingSystem;
    }

    [[nodiscard]] const std::string& OperatingSystemVersion() const noexcept
    {
        return m_operatingSystemVersion;
    }

    [[nodiscard]] const tailgate::crypto::Bytes32& NodePublicKey() const noexcept
    {
        return m_nodePublicKey;
    }

    [[nodiscard]] const tailgate::crypto::Bytes32& ClientNonce() const noexcept
    {
        return m_clientNonce;
    }

    [[nodiscard]] const tailgate::crypto::Bytes32& ClientProof() const noexcept
    {
        return m_clientProof;
    }

private:
    std::string m_tailnet;
    std::uint64_t m_nodeId;
    std::string m_hostname;
    std::string m_operatingSystem;
    std::string m_operatingSystemVersion;
    tailgate::crypto::Bytes32 m_nodePublicKey;
    tailgate::crypto::Bytes32 m_clientNonce;
    tailgate::crypto::Bytes32 m_clientProof;
};

class Challenge
{
public:
    Challenge(tailgate::crypto::Bytes32 relayPublicKey,
              tailgate::crypto::Bytes32 serverNonce) noexcept
        : m_relayPublicKey(relayPublicKey), m_serverNonce(serverNonce)
    {
    }

    [[nodiscard]] const tailgate::crypto::Bytes32& RelayPublicKey() const noexcept
    {
        return m_relayPublicKey;
    }

    [[nodiscard]] const tailgate::crypto::Bytes32& ServerNonce() const noexcept
    {
        return m_serverNonce;
    }

private:
    tailgate::crypto::Bytes32 m_relayPublicKey;
    tailgate::crypto::Bytes32 m_serverNonce;
};

class Session
{
public:
    Session(std::string tailnet,
            std::string relayHostName,
            std::string relayHostAddress,
            tailgate::crypto::Bytes32 serverProof)
        : m_tailnet(std::move(tailnet)),
          m_relayHostName(std::move(relayHostName)),
          m_relayHostAddress(std::move(relayHostAddress)),
          m_serverProof(serverProof)
    {
    }

    [[nodiscard]] const std::string& Tailnet() const noexcept
    {
        return m_tailnet;
    }

    [[nodiscard]] const std::string& RelayHostName() const noexcept
    {
        return m_relayHostName;
    }

    [[nodiscard]] const std::string& RelayHostAddress() const noexcept
    {
        return m_relayHostAddress;
    }

    [[nodiscard]] const tailgate::crypto::Bytes32& ServerProof() const noexcept
    {
        return m_serverProof;
    }

private:
    std::string m_tailnet;
    std::string m_relayHostName;
    std::string m_relayHostAddress;
    tailgate::crypto::Bytes32 m_serverProof;
};

class Rejection
{
public:
    explicit Rejection(std::string reason) : m_reason(std::move(reason))
    {
    }

    [[nodiscard]] const std::string& Reason() const noexcept
    {
        return m_reason;
    }

private:
    std::string m_reason;
};

class DerpRoute
{
public:
    DerpRoute(std::uint64_t token, std::uint16_t region) noexcept : m_token(token), m_region(region)
    {
    }

    [[nodiscard]] std::uint64_t Token() const noexcept
    {
        return m_token;
    }

    [[nodiscard]] std::uint16_t Region() const noexcept
    {
        return m_region;
    }

    [[nodiscard]] bool operator==(const DerpRoute&) const noexcept = default;

private:
    std::uint64_t m_token;
    std::uint16_t m_region;
};

class PeerPacket
{
public:
    PeerPacket(tailgate::crypto::Bytes32 peer,
               std::vector<std::uint8_t> payload,
               bool control = false,
               bool disco = false,
               std::uint32_t endpointAddress = 0,
               std::uint16_t endpointPort = 0,
               std::optional<DerpRoute> derpRoute = std::nullopt)
        : m_peer(peer),
          m_payload(std::move(payload)),
          m_control(control),
          m_disco(disco),
          m_endpointAddress(endpointAddress),
          m_endpointPort(endpointPort),
          m_derpRoute(std::move(derpRoute))
    {
    }

    [[nodiscard]] const tailgate::crypto::Bytes32& Peer() const noexcept
    {
        return m_peer;
    }

    [[nodiscard]] const std::vector<std::uint8_t>& Payload() const noexcept
    {
        return m_payload;
    }

    [[nodiscard]] bool Control() const noexcept
    {
        return m_control;
    }

    [[nodiscard]] bool Disco() const noexcept
    {
        return m_disco;
    }

    [[nodiscard]] std::uint32_t EndpointAddress() const noexcept
    {
        return m_endpointAddress;
    }

    [[nodiscard]] std::uint16_t EndpointPort() const noexcept
    {
        return m_endpointPort;
    }

    [[nodiscard]] const std::optional<DerpRoute>& DerpIngressRoute() const noexcept
    {
        return m_derpRoute;
    }

private:
    tailgate::crypto::Bytes32 m_peer;
    std::vector<std::uint8_t> m_payload;
    bool m_control;
    bool m_disco;
    std::uint32_t m_endpointAddress;
    std::uint16_t m_endpointPort;
    std::optional<DerpRoute> m_derpRoute;
};

class PeerEndpoint
{
public:
    PeerEndpoint(tailgate::crypto::Bytes32 peer, tailgate::net::Endpoint endpoint) noexcept
        : m_peer(peer), m_endpoint(endpoint)
    {
    }

    [[nodiscard]] const tailgate::crypto::Bytes32& Peer() const noexcept
    {
        return m_peer;
    }

    [[nodiscard]] const tailgate::net::Endpoint& Endpoint() const noexcept
    {
        return m_endpoint;
    }

private:
    tailgate::crypto::Bytes32 m_peer;
    tailgate::net::Endpoint m_endpoint;
};

class ServerEndpointCandidates
{
public:
    static constexpr std::size_t MaximumCount = 16;

    explicit ServerEndpointCandidates(std::vector<tailgate::net::Endpoint> endpoints)
        : m_endpoints(std::move(endpoints))
    {
    }

    [[nodiscard]] const std::vector<tailgate::net::Endpoint>& Endpoints() const noexcept
    {
        return m_endpoints;
    }

private:
    std::vector<tailgate::net::Endpoint> m_endpoints;
};

class DerpAuthenticationChallenge
{
public:
    DerpAuthenticationChallenge(std::uint64_t requestId,
                                tailgate::crypto::Bytes32 serverKey) noexcept
        : m_requestId(requestId), m_serverKey(serverKey)
    {
    }

    [[nodiscard]] std::uint64_t RequestId() const noexcept
    {
        return m_requestId;
    }

    [[nodiscard]] const tailgate::crypto::Bytes32& ServerKey() const noexcept
    {
        return m_serverKey;
    }

private:
    std::uint64_t m_requestId;
    tailgate::crypto::Bytes32 m_serverKey;
};

class DerpAuthenticationResponse
{
public:
    DerpAuthenticationResponse(std::uint64_t requestId, std::vector<std::uint8_t> clientInfo)
        : m_requestId(requestId), m_clientInfo(std::move(clientInfo))
    {
    }

    [[nodiscard]] std::uint64_t RequestId() const noexcept
    {
        return m_requestId;
    }

    [[nodiscard]] const std::vector<std::uint8_t>& ClientInfo() const noexcept
    {
        return m_clientInfo;
    }

private:
    std::uint64_t m_requestId;
    std::vector<std::uint8_t> m_clientInfo;
};

class ProtocolCodec final
{
public:
    [[nodiscard]] static std::vector<std::uint8_t>
    EncodeAuthentication(const Authentication& authentication);
    [[nodiscard]] static Authentication
    DecodeAuthentication(const std::vector<std::uint8_t>& payload);
    [[nodiscard]] static std::vector<std::uint8_t> EncodeChallenge(const Challenge& challenge);
    [[nodiscard]] static Challenge DecodeChallenge(const std::vector<std::uint8_t>& payload);
    [[nodiscard]] static std::vector<std::uint8_t> EncodeSession(const Session& session);
    [[nodiscard]] static Session DecodeSession(const std::vector<std::uint8_t>& payload);
    [[nodiscard]] static std::vector<std::uint8_t> EncodeRejection(const Rejection& rejection);
    [[nodiscard]] static Rejection DecodeRejection(const std::vector<std::uint8_t>& payload);
    [[nodiscard]] static std::vector<std::uint8_t> EncodePeerPacket(const PeerPacket& packet);
    [[nodiscard]] static PeerPacket DecodePeerPacket(const std::vector<std::uint8_t>& payload);
    [[nodiscard]] static std::vector<std::uint8_t> EncodePeerEndpoint(const PeerEndpoint& endpoint);
    [[nodiscard]] static PeerEndpoint DecodePeerEndpoint(const std::vector<std::uint8_t>& payload);
    [[nodiscard]] static std::vector<std::uint8_t>
    EncodeServerEndpointCandidates(const ServerEndpointCandidates& candidates);
    [[nodiscard]] static ServerEndpointCandidates
    DecodeServerEndpointCandidates(const std::vector<std::uint8_t>& payload);
    [[nodiscard]] static std::vector<std::uint8_t>
    EncodeDerpChallenge(const DerpAuthenticationChallenge& challenge);
    [[nodiscard]] static DerpAuthenticationChallenge
    DecodeDerpChallenge(const std::vector<std::uint8_t>& payload);
    [[nodiscard]] static std::vector<std::uint8_t>
    EncodeDerpResponse(const DerpAuthenticationResponse& response);
    [[nodiscard]] static DerpAuthenticationResponse
    DecodeDerpResponse(const std::vector<std::uint8_t>& payload);
    [[nodiscard]] static std::vector<std::uint8_t>
    EncodeNetworkConfig(const tailgate::types::netmap::NetworkConfig& config);
    [[nodiscard]] static tailgate::types::netmap::NetworkConfig
    DecodeNetworkConfig(const std::vector<std::uint8_t>& payload);
};

[[nodiscard]] tailgate::crypto::Bytes32
CreateClientProof(const tailgate::crypto::Bytes32& clientPrivateKey,
                  const tailgate::crypto::Bytes32& relayPublicKey,
                  const tailgate::crypto::Bytes32& serverNonce,
                  const tailgate::crypto::Bytes32& clientNonce);
[[nodiscard]] tailgate::crypto::Bytes32
CreateServerProof(const tailgate::crypto::Bytes32& relayPrivateKey,
                  const tailgate::crypto::Bytes32& clientPublicKey,
                  const tailgate::crypto::Bytes32& serverNonce,
                  const tailgate::crypto::Bytes32& clientNonce);
[[nodiscard]] bool ProofMatches(const tailgate::crypto::Bytes32& expected,
                                const tailgate::crypto::Bytes32& actual);
void AcceptHttpUpgrade(tailgate::base::ByteStream& stream);
[[nodiscard]] std::vector<std::uint8_t> RequestHttpUpgrade(tailgate::base::ByteStream& stream,
                                                           const std::string& host);

enum class DecoderReadStatus
{
    WouldBlock,
    Closed,
};

struct DecoderReadResult
{
    std::vector<Frame> Frames;
    DecoderReadStatus Status = DecoderReadStatus::WouldBlock;
};

class Decoder final
{
public:
    void Feed(const std::uint8_t* data, std::size_t size);
    void Feed(const std::vector<std::uint8_t>& data);
    [[nodiscard]] std::optional<Frame> Next();
    [[nodiscard]] Frame Read(tailgate::base::ByteStream& stream);
    [[nodiscard]] DecoderReadResult ReadAvailable(tailgate::base::ByteStream& stream,
                                                  std::size_t maximumReadSize);
    [[nodiscard]] std::size_t BufferedBytes() const;

private:
    std::vector<std::uint8_t> m_buffer;
    std::size_t m_offset = 0;
};

} // namespace tailgate::hosted
