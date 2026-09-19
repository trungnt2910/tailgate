#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/disco/Disco.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::hosted
{

enum class ClientError
{
    IdentityChanged,
    NotActive,
};

class ClientException final : public std::runtime_error
{
public:
    explicit ClientException(ClientError error);

    [[nodiscard]] ClientError Error() const noexcept;

private:
    ClientError m_error;
};

struct ClientConfig
{
    tailgate::crypto::Bytes32 NodePrivateKey{};
    tailgate::crypto::Bytes32 NodePublicKey{};
    tailgate::crypto::Bytes32 DiscoPrivateKey{};
    tailgate::types::netmap::NetworkConfig Network;
    std::string ExitNode;
};

struct DiscoPong
{
    tailgate::disco::Disco::Message Message;
    PeerPacket Packet;
};

struct AuthenticatedPacket
{
    tailgate::crypto::Bytes32 Peer{};
    std::vector<std::uint8_t> Bytes;
};

struct ClientProcessResult
{
    std::vector<AuthenticatedPacket> LocalPackets;
    std::vector<std::uint8_t> RemoteOutput;
    std::optional<DiscoPong> Pong;
    std::optional<std::uint64_t> PumpReply;
    bool NetworkMapChanged = false;
    bool DataPathReady = false;
};

class Client final
{
public:
    Client();
    ~Client();

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) noexcept;
    Client& operator=(Client&&) noexcept;

    [[nodiscard]] std::vector<std::uint8_t> Start(ClientConfig config);
    void Stop() noexcept;

    [[nodiscard]] bool Active() const noexcept;
    [[nodiscard]] const tailgate::types::netmap::NetworkConfig& Network() const;
    [[nodiscard]] tailgate::disco::Disco& Disco();
    [[nodiscard]] const std::string& ExitNode() const noexcept;

    [[nodiscard]] std::vector<std::uint8_t> Encapsulate(const std::vector<std::uint8_t>& packet);
    [[nodiscard]] std::vector<std::uint8_t> EncapsulateTo(const tailgate::crypto::Bytes32& peer,
                                                          const std::vector<std::uint8_t>& packet);
    [[nodiscard]] ClientProcessResult Process(const Frame& frame);
    [[nodiscard]] std::vector<std::uint8_t> UpdateTimers();
    // Inactive clients produce no transport bytes, including during reconnect setup.
    [[nodiscard]] std::vector<std::uint8_t> BuildKeepAlive();
    [[nodiscard]] std::vector<std::uint8_t> ProbePeers();
    [[nodiscard]] std::vector<std::uint8_t>
    UpdateNetworkMap(tailgate::types::netmap::NetworkConfig config,
                     std::optional<std::string> exitNode = std::nullopt);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace tailgate::hosted
