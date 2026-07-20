#include "TcpStream.h"

#include <cerrno>
#include <cstring>
#include <format>
#include <stdexcept>

#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

namespace tailgate::linux_frontend
{
namespace
{

constexpr int MillisecondsPerSecond = 1000;

// Connects with a bounded wait: a blocking connect() would otherwise wait for the kernel
// default (minutes) when the endpoint drops packets.
bool ConnectWithTimeout(int fd,
                        const sockaddr* address,
                        socklen_t addressLength,
                        int timeoutSeconds)
{
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
    {
        return false;
    }
    bool connected = connect(fd, address, addressLength) == 0;
    if (!connected && errno == EINPROGRESS)
    {
        pollfd waiter{};
        waiter.fd = fd;
        waiter.events = POLLOUT;
        if (poll(&waiter, 1, timeoutSeconds * MillisecondsPerSecond) == 1)
        {
            int socketError = 0;
            socklen_t errorLength = sizeof(socketError);
            connected = getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &errorLength) == 0 &&
                        socketError == 0;
        }
    }
    return connected && fcntl(fd, F_SETFL, flags) == 0;
}

} // namespace

TcpStream::TcpStream(const std::string& host,
                     const std::string& service,
                     const std::string& interfaceName,
                     int ioTimeoutSeconds,
                     int connectTimeoutSeconds)
{
    if (ioTimeoutSeconds <= 0)
    {
        throw std::runtime_error("TCP stream timeout must be positive");
    }
    if (connectTimeoutSeconds <= 0)
    {
        connectTimeoutSeconds = ioTimeoutSeconds;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* results = nullptr;
    int gai = getaddrinfo(host.c_str(), service.c_str(), &hints, &results);
    if (gai != 0)
    {
        throw std::runtime_error("getaddrinfo failed: " + std::string(gai_strerror(gai)));
    }

    for (addrinfo* entry = results; entry != nullptr; entry = entry->ai_next)
    {
        int fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (fd < 0)
        {
            continue;
        }
        if (!interfaceName.empty() &&
            setsockopt(
                fd, SOL_SOCKET, SO_BINDTODEVICE, interfaceName.c_str(), interfaceName.size() + 1) !=
                0)
        {
            close(fd);
            freeaddrinfo(results);
            throw std::runtime_error(std::format(
                "failed to bind TCP transport to {}: {}", interfaceName, std::strerror(errno)));
        }
        if (ConnectWithTimeout(fd, entry->ai_addr, entry->ai_addrlen, connectTimeoutSeconds))
        {
            m_fd = fd;
            break;
        }
        close(fd);
    }
    freeaddrinfo(results);

    if (m_fd < 0)
    {
        throw std::runtime_error(
            std::format("failed to connect TCP stream to {}:{}", host, service));
    }

    int noDelay = 1;
    if (setsockopt(m_fd, IPPROTO_TCP, TCP_NODELAY, &noDelay, sizeof(noDelay)) != 0)
    {
        throw std::runtime_error("failed to enable TCP_NODELAY: " +
                                 std::string(std::strerror(errno)));
    }

    timeval timeout{};
    timeout.tv_sec = ioTimeoutSeconds;
    setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(m_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

TcpStream::~TcpStream()
{
    if (m_fd >= 0)
    {
        close(m_fd);
    }
}

std::optional<std::size_t> TcpStream::TryWriteSome(const std::uint8_t* data, std::size_t size)
{
    const ssize_t result = send(m_fd, data, size, MSG_NOSIGNAL);
    if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
        return std::nullopt;
    }
    if (result < 0)
    {
        throw std::runtime_error("send failed: " + std::string(std::strerror(errno)));
    }
    return static_cast<std::size_t>(result);
}

std::optional<std::vector<std::uint8_t>> TcpStream::TryReadSome(std::size_t maxBytes)
{
    std::vector<std::uint8_t> data(maxBytes);
    ssize_t result = recv(m_fd, data.data(), data.size(), 0);
    if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
        return std::nullopt;
    }
    if (result < 0)
    {
        throw std::runtime_error("recv failed: " + std::string(std::strerror(errno)));
    }
    data.resize(static_cast<std::size_t>(result));
    return data;
}

int TcpStream::NativeHandle() const
{
    return m_fd;
}

void TcpStream::SetNonBlocking(bool enabled)
{
    const int flags = fcntl(m_fd, F_GETFL, 0);
    if (flags < 0 || fcntl(m_fd, F_SETFL, enabled ? flags | O_NONBLOCK : flags & ~O_NONBLOCK) != 0)
    {
        throw std::runtime_error("failed to configure TCP blocking mode");
    }
}

} // namespace tailgate::linux_frontend
