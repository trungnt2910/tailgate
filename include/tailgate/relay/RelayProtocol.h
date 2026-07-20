#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "tailgate/ByteStream.h"
#include "tailgate/control/NetworkMap.h"
#include "tailgate/protocol/Crypto.h"
#include "tailgate/protocol/Disco.h"

namespace tailgate::relay
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
};

struct Frame
{
    MessageType Type = MessageType::Error;
    std::vector<std::uint8_t> Payload;
};

struct Authentication
{
    std::string Tailnet;
    std::uint64_t NodeId = 0;
    std::string Hostname;
    std::string OperatingSystem;
    std::string OperatingSystemVersion;
    protocol::Bytes32 NodePublicKey{};
    protocol::Bytes32 ClientNonce{};
    protocol::Bytes32 ClientProof{};
};

struct Challenge
{
    protocol::Bytes32 RelayPublicKey{};
    protocol::Bytes32 ServerNonce{};
};

struct Session
{
    std::string Tailnet;
    std::string RelayHostName;
    std::string RelayHostAddress;
    protocol::Bytes32 ServerProof{};
};

struct Rejection
{
    std::string Reason;
};

struct PeerPacket
{
    protocol::Bytes32 Peer{};
    std::vector<std::uint8_t> Payload;
    bool Control = false;
    bool Disco = false;
    std::uint32_t EndpointAddress = 0;
    std::uint16_t EndpointPort = 0;
};

struct DerpAuthenticationChallenge
{
    std::uint64_t RequestId = 0;
    protocol::Bytes32 ServerKey{};
};

struct DerpAuthenticationResponse
{
    std::uint64_t RequestId = 0;
    std::vector<std::uint8_t> ClientInfo;
};

[[nodiscard]] std::vector<std::uint8_t> Encode(const Frame& frame);
[[nodiscard]] std::vector<std::uint8_t> EncodeAuthentication(const Authentication& authentication);
[[nodiscard]] Authentication DecodeAuthentication(const std::vector<std::uint8_t>& payload);
[[nodiscard]] std::vector<std::uint8_t> EncodeChallenge(const Challenge& challenge);
[[nodiscard]] Challenge DecodeChallenge(const std::vector<std::uint8_t>& payload);
[[nodiscard]] std::vector<std::uint8_t> EncodeSession(const Session& session);
[[nodiscard]] Session DecodeSession(const std::vector<std::uint8_t>& payload);
[[nodiscard]] std::vector<std::uint8_t> EncodeRejection(const Rejection& rejection);
[[nodiscard]] Rejection DecodeRejection(const std::vector<std::uint8_t>& payload);
[[nodiscard]] std::vector<std::uint8_t> EncodePeerPacket(const PeerPacket& packet);
[[nodiscard]] PeerPacket DecodePeerPacket(const std::vector<std::uint8_t>& payload);
[[nodiscard]] std::vector<std::uint8_t>
EncodeDerpChallenge(const DerpAuthenticationChallenge& challenge);
[[nodiscard]] DerpAuthenticationChallenge
DecodeDerpChallenge(const std::vector<std::uint8_t>& payload);
[[nodiscard]] std::vector<std::uint8_t>
EncodeDerpResponse(const DerpAuthenticationResponse& response);
[[nodiscard]] DerpAuthenticationResponse
DecodeDerpResponse(const std::vector<std::uint8_t>& payload);
[[nodiscard]] protocol::Bytes32 CreateClientProof(const protocol::Bytes32& clientPrivateKey,
                                                  const protocol::Bytes32& relayPublicKey,
                                                  const protocol::Bytes32& serverNonce,
                                                  const protocol::Bytes32& clientNonce);
[[nodiscard]] protocol::Bytes32 CreateServerProof(const protocol::Bytes32& relayPrivateKey,
                                                  const protocol::Bytes32& clientPublicKey,
                                                  const protocol::Bytes32& serverNonce,
                                                  const protocol::Bytes32& clientNonce);
[[nodiscard]] bool ProofMatches(const protocol::Bytes32& expected, const protocol::Bytes32& actual);
[[nodiscard]] std::vector<std::uint8_t> EncodeNetworkConfig(const control::NetworkConfig& config);
[[nodiscard]] control::NetworkConfig DecodeNetworkConfig(const std::vector<std::uint8_t>& payload);

// Builds one disco ping per online peer with valid node and disco keys. Hosted clients send
// these on each server heartbeat so the relay keeps forwarding traffic into DERP, which both
// keeps the hosted DERP connection registered and advertises the client's disco reachability.
[[nodiscard]] std::vector<PeerPacket>
BuildDiscoProbes(const protocol::Disco& disco, const std::vector<control::PeerConfig>& peers);
void AcceptHttpUpgrade(IByteStream& stream);
[[nodiscard]] std::vector<std::uint8_t> RequestHttpUpgrade(IByteStream& stream,
                                                           const std::string& host);

class Decoder final
{
public:
    void Feed(const std::uint8_t* data, std::size_t size);
    void Feed(const std::vector<std::uint8_t>& data);
    [[nodiscard]] std::optional<Frame> Next();
    [[nodiscard]] std::size_t BufferedBytes() const;

private:
    std::vector<std::uint8_t> m_buffer;
    std::size_t m_offset = 0;
};

void WriteFrame(IByteStream& stream, const Frame& frame);
[[nodiscard]] Frame ReadFrame(IByteStream& stream, Decoder& decoder);

} // namespace tailgate::relay
