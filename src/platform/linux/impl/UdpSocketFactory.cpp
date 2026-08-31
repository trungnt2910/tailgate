#include "UdpSocketFactory.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <tailgate/net/Endpoint.h>
#include <tailgate/types/nettype/UdpSocket.h>

#include "UniqueFd.h"

namespace tailgate::linux_frontend::impl
{
namespace
{

constexpr int TransportBufferBytes = 4 * 1024 * 1024;

sockaddr_in NativeEndpoint(const tailgate::net::Endpoint& endpoint)
{
    sockaddr_in result{};
    result.sin_family = AF_INET;
    result.sin_addr.s_addr = htonl(endpoint.Address().HostOrder());
    result.sin_port = htons(endpoint.Port());
    return result;
}

tailgate::net::Endpoint PortableEndpoint(const sockaddr_in& endpoint)
{
    return tailgate::net::Endpoint(
        tailgate::net::Ipv4Address::FromHostOrder(ntohl(endpoint.sin_addr.s_addr)),
        ntohs(endpoint.sin_port));
}

bool IsUnavailableSendError(int error) noexcept
{
    switch (error)
    {
    case EACCES:
    case EADDRNOTAVAIL:
    case EHOSTDOWN:
    case EHOSTUNREACH:
    case EMSGSIZE:
    case ENETDOWN:
    case ENETUNREACH:
    case EPERM:
        return true;
    default:
        return false;
    }
}

class UdpSocket final : public tailgate::types::nettype::UdpSocket
{
public:
    UdpSocket(UniqueFd descriptor,
              std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> eventRegistry,
              tailgate::base::EventToken readinessToken)
        : m_descriptor(std::move(descriptor)),
          m_eventRegistry(std::move(eventRegistry)),
          m_readinessToken(readinessToken)
    {
        if (m_readinessToken.Value != 0)
        {
            m_eventHandle =
                m_eventRegistry->Register(m_descriptor.Fd,
                                          tailgate::linux_frontend::event::EventInterest::Readable,
                                          m_readinessToken);
        }
    }

    ~UdpSocket() override
    {
        Close();
    }

    tailgate::types::nettype::SocketIoResult
    TrySendTo(const tailgate::net::Endpoint& destination,
              const std::vector<std::uint8_t>& payload) override
    {
        if (m_descriptor.Fd < 0)
        {
            return tailgate::types::nettype::SocketIoResult::Closed;
        }
        const sockaddr_in endpoint = NativeEndpoint(destination);
        const ssize_t sent = sendto(m_descriptor.Fd,
                                    payload.data(),
                                    payload.size(),
                                    MSG_DONTWAIT,
                                    reinterpret_cast<const sockaddr*>(&endpoint),
                                    sizeof(endpoint));
        if (sent == static_cast<ssize_t>(payload.size()))
        {
            return tailgate::types::nettype::SocketIoResult::Complete;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS))
        {
            return tailgate::types::nettype::SocketIoResult::WouldBlock;
        }
        if (sent < 0 && (errno == EBADF || errno == ENOTSOCK))
        {
            return tailgate::types::nettype::SocketIoResult::Closed;
        }
        if (sent >= 0 || IsUnavailableSendError(errno))
        {
            return tailgate::types::nettype::SocketIoResult::Unavailable;
        }
        throw std::system_error(errno, std::generic_category());
    }

    tailgate::types::nettype::UdpReceiveResult TryReceive(std::size_t maximumSize) override
    {
        if (m_descriptor.Fd < 0)
        {
            return tailgate::types::nettype::UdpReceiveResult{
                .Result = tailgate::types::nettype::SocketIoResult::Closed,
                .Datagram = {},
            };
        }
        std::vector<std::uint8_t> payload(maximumSize);
        sockaddr_in source{};
        socklen_t sourceSize = sizeof(source);
        const ssize_t received = recvfrom(m_descriptor.Fd,
                                          payload.data(),
                                          payload.size(),
                                          MSG_DONTWAIT,
                                          reinterpret_cast<sockaddr*>(&source),
                                          &sourceSize);
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            return {};
        }
        if (received < 0 && (errno == EBADF || errno == ENOTSOCK))
        {
            return tailgate::types::nettype::UdpReceiveResult{
                .Result = tailgate::types::nettype::SocketIoResult::Closed,
                .Datagram = {},
            };
        }
        if (received < 0)
        {
            throw std::system_error(errno, std::generic_category());
        }
        payload.resize(static_cast<std::size_t>(received));
        return tailgate::types::nettype::UdpReceiveResult{
            .Result = tailgate::types::nettype::SocketIoResult::Complete,
            .Datagram =
                tailgate::types::nettype::UdpDatagram{
                    .Source = PortableEndpoint(source),
                    .Payload = std::move(payload),
                },
        };
    }

    tailgate::net::Endpoint LocalEndpoint() const override
    {
        if (m_descriptor.Fd < 0)
        {
            return {};
        }
        sockaddr_in endpoint{};
        socklen_t endpointSize = sizeof(endpoint);
        if (getsockname(m_descriptor.Fd, reinterpret_cast<sockaddr*>(&endpoint), &endpointSize) !=
            0)
        {
            throw std::system_error(errno, std::generic_category());
        }
        return PortableEndpoint(endpoint);
    }

    void SetWriteInterest(bool enabled) override
    {
        if (m_readinessToken.Value == 0 || m_writeInterest == enabled)
        {
            return;
        }
        const tailgate::linux_frontend::event::EventInterest interest =
            enabled ? tailgate::linux_frontend::event::EventInterest::Readable |
                          tailgate::linux_frontend::event::EventInterest::Writable
                    : tailgate::linux_frontend::event::EventInterest::Readable;
        m_eventHandle.Modify(interest);
        m_writeInterest = enabled;
    }

    void Close() noexcept override
    {
        m_eventHandle.Reset();
        m_descriptor.Reset();
    }

private:
    UniqueFd m_descriptor;
    std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> m_eventRegistry;
    tailgate::linux_frontend::event::EventHandle m_eventHandle;
    tailgate::base::EventToken m_readinessToken;
    bool m_writeInterest = false;
};

UniqueFd OpenDescriptor(const tailgate::types::nettype::UdpSocketOptions& options)
{
    UniqueFd descriptor(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP));
    if (descriptor.Fd < 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    (void)setsockopt(
        descriptor.Fd, SOL_SOCKET, SO_RCVBUF, &TransportBufferBytes, sizeof(TransportBufferBytes));
    (void)setsockopt(
        descriptor.Fd, SOL_SOCKET, SO_SNDBUF, &TransportBufferBytes, sizeof(TransportBufferBytes));
    const int flags = fcntl(descriptor.Fd, F_GETFL, 0);
    if (flags < 0 || fcntl(descriptor.Fd, F_SETFL, flags | O_NONBLOCK) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    if (options.NetworkInterface && setsockopt(descriptor.Fd,
                                               SOL_SOCKET,
                                               SO_BINDTODEVICE,
                                               options.NetworkInterface->c_str(),
                                               options.NetworkInterface->size() + 1) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    const sockaddr_in bindEndpoint = NativeEndpoint(options.BindEndpoint);
    if (bind(descriptor.Fd,
             reinterpret_cast<const sockaddr*>(&bindEndpoint),
             sizeof(bindEndpoint)) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    return descriptor;
}

} // namespace

UdpSocketFactory::UdpSocketFactory(
    std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> eventRegistry)
    : m_eventRegistry(std::move(eventRegistry))
{
}

std::unique_ptr<tailgate::types::nettype::UdpSocket>
UdpSocketFactory::OpenUdpSocket(const tailgate::types::nettype::UdpSocketOptions& options)
{
    return std::make_unique<UdpSocket>(
        OpenDescriptor(options), m_eventRegistry, options.ReadinessToken);
}

} // namespace tailgate::linux_frontend::impl
