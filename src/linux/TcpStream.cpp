#include "TcpStream.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

namespace tailgate::linux_frontend
{

TcpStream::TcpStream(const std::string& host,
                     const std::string& service,
                     const std::string& interfaceName)
{
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
            throw std::runtime_error("failed to bind TCP transport to " + interfaceName + ": " +
                                     std::string(std::strerror(errno)));
        }
        if (connect(fd, entry->ai_addr, entry->ai_addrlen) == 0)
        {
            m_fd = fd;
            break;
        }
        close(fd);
    }
    freeaddrinfo(results);

    if (m_fd < 0)
    {
        throw std::runtime_error("failed to connect TCP stream to " + host + ":" + service);
    }

    timeval timeout{};
    timeout.tv_sec = 15;
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
