#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>

#include <tailgate/base/ByteStream.h>
#include <tailgate/base/EventLoop.h>

namespace tailgate::types::nettype
{

struct TcpSocketOptions
{
    std::string ConnectAddress;
    std::string Service;
    std::optional<std::string> NetworkInterface;
    std::optional<std::string> TlsServerName;
    std::chrono::seconds IoTimeout{20};
    std::optional<std::chrono::seconds> ConnectTimeout;
    tailgate::base::EventToken ReadinessToken;
    bool AllowTls13 = false;
    bool NonBlockingAfterConnect = false;
};

class TcpSocket : public tailgate::base::ByteStream
{
public:
    ~TcpSocket() override;

    virtual void SetReadTimeout(std::optional<std::chrono::seconds> timeout) = 0;
    virtual void SetWriteInterest(bool enabled) = 0;
    virtual void SetNonBlocking(bool enabled) = 0;
    virtual void Close() noexcept = 0;
};

class TcpSocketFactory
{
public:
    virtual ~TcpSocketFactory();

    [[nodiscard]] virtual std::unique_ptr<TcpSocket>
    OpenTcpSocket(const TcpSocketOptions& options) = 0;
};

} // namespace tailgate::types::nettype
