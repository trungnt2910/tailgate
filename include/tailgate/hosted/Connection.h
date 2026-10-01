#pragma once

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::hosted
{

enum class ConnectionError
{
    ChallengeExpected,
    Rejected,
    AuthenticationExpected,
    SessionIdentityInvalid,
};

class ConnectionException final : public std::runtime_error
{
public:
    explicit ConnectionException(ConnectionError error, std::string reason = {});

    [[nodiscard]] ConnectionError Error() const noexcept;
    [[nodiscard]] const std::string& Reason() const noexcept;

private:
    ConnectionError m_error;
    std::string m_reason;
};

struct ConnectionOptions
{
    tailgate::types::nettype::TcpSocketOptions Socket;
    std::string HttpHost;
    std::string Hostname;
    std::string OperatingSystem;
    std::string OperatingSystemVersion;
    ClientConfig Client;
};

struct ConnectionResult
{
    std::unique_ptr<tailgate::types::nettype::TcpSocket> Stream;
    tailgate::crypto::Bytes32 RelayPublicKey{};
    Session RelaySession;
    Decoder FrameDecoder;
    ClientConfig Configuration;
    ConnectionOptions Reconnect;
};

class Connection final
{
public:
    explicit Connection(tailgate::types::nettype::TcpSocketFactory& sockets) noexcept;

    [[nodiscard]] ConnectionResult Connect(ConnectionOptions options);

private:
    tailgate::types::nettype::TcpSocketFactory& m_sockets;
};

} // namespace tailgate::hosted
