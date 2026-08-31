#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/base/EventLoop.h>
#include <tailgate/net/Endpoint.h>

namespace tailgate::types::nettype
{

enum class SocketIoResult
{
    Complete,
    WouldBlock,
    Unavailable,
    Closed,
};

struct UdpDatagram
{
    tailgate::net::Endpoint Source;
    std::vector<std::uint8_t> Payload;
};

struct UdpReceiveResult
{
    SocketIoResult Result = SocketIoResult::WouldBlock;
    UdpDatagram Datagram;
};

class UdpSocket
{
public:
    virtual ~UdpSocket();

    [[nodiscard]] virtual SocketIoResult TrySendTo(const tailgate::net::Endpoint& destination,
                                                   const std::vector<std::uint8_t>& payload) = 0;
    [[nodiscard]] virtual UdpReceiveResult TryReceive(std::size_t maximumSize) = 0;
    [[nodiscard]] virtual tailgate::net::Endpoint LocalEndpoint() const = 0;
    virtual void SetWriteInterest(bool enabled) = 0;
    virtual void Close() noexcept = 0;
};

struct UdpSocketOptions
{
    tailgate::net::Endpoint BindEndpoint;
    std::optional<std::string> NetworkInterface;
    tailgate::base::EventToken ReadinessToken;
};

class UdpSocketFactory
{
public:
    virtual ~UdpSocketFactory();

    // Must return without waiting for platform I/O. A socket whose native setup is still pending
    // reports SocketIoResult::WouldBlock until the event loop delivers its readiness event.
    [[nodiscard]] virtual std::unique_ptr<UdpSocket>
    OpenUdpSocket(const UdpSocketOptions& options) = 0;
};

} // namespace tailgate::types::nettype
