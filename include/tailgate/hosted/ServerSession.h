#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::hosted
{

enum class ServerSessionError
{
    InvalidState,
    UnexpectedFrame,
    NetworkMapIdentityChanged,
    InvalidTailnetDnsQuery,
};

class ServerSessionException final : public std::runtime_error
{
public:
    explicit ServerSessionException(ServerSessionError error);

    [[nodiscard]] ServerSessionError Error() const noexcept;

private:
    ServerSessionError m_error;
};

struct ServerSessionOptions
{
    std::string ExpectedTailnet;
    std::string RelayHostName;
    std::string RelayHostAddress;
    tailgate::crypto::Bytes32 RelayPrivateKey{};
    tailgate::crypto::Bytes32 RelayPublicKey{};
};

struct ServerAuthenticationResult
{
    Authentication Identity;
    bool ProofValid = false;
    bool TailnetMatches = false;
};

struct ServerDerpChallenge
{
    std::uint64_t RequestId = 0;
    Frame Output;
};

struct ServerSessionProcessResult
{
    std::optional<std::vector<std::uint8_t>> PeerPacketPayload;
    std::optional<PeerEndpoint> VerifiedPeerEndpoint;
    std::optional<tailgate::types::netmap::NetworkConfig> NetworkMap;
    std::optional<DerpAuthenticationResponse> DerpResponse;
    std::vector<Frame> RemoteOutput;
    std::optional<std::string> DnsName;
    bool ClientReady = false;
    bool Shutdown = false;
};

class ServerSession
{
public:
    virtual ~ServerSession();

    [[nodiscard]] virtual Frame StartAuthentication() = 0;
    [[nodiscard]] virtual ServerAuthenticationResult EvaluateAuthentication(const Frame& frame) = 0;
    [[nodiscard]] virtual Frame CompleteAuthentication(bool nodeVisible) = 0;
    [[nodiscard]] virtual tailgate::types::netmap::NetworkConfig
    AcceptInitialNetworkMap(const Frame& frame) = 0;
    [[nodiscard]] virtual ServerSessionProcessResult Process(const Frame& frame) = 0;
    [[nodiscard]] virtual ServerDerpChallenge
    BuildDerpChallenge(const tailgate::crypto::Bytes32& serverKey) = 0;
    [[nodiscard]] virtual Frame BuildHeartbeat() const = 0;
    [[nodiscard]] virtual Frame
    BuildServerPacket(std::vector<std::uint8_t> peerPacketPayload) const = 0;

protected:
    ServerSession() = default;
};

class ServerSessionFactory
{
public:
    virtual ~ServerSessionFactory();

    [[nodiscard]] virtual std::unique_ptr<ServerSession>
    CreateServerSession(ServerSessionOptions options) = 0;

protected:
    ServerSessionFactory() = default;
};

} // namespace tailgate::hosted
