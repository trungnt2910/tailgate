#pragma once

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/types/nettype/TcpSocket.h>
#include <tailgate/wgengine/tstun/Device.h>

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
};

class Connection final
{
public:
    Connection(tailgate::wgengine::tstun::Device& device,
               tailgate::hosted::Client& client) noexcept;

    [[nodiscard]] ConnectionResult Connect(ConnectionOptions options);

private:
    tailgate::wgengine::tstun::Device& m_device;
    tailgate::hosted::Client& m_client;
};

} // namespace tailgate::hosted
