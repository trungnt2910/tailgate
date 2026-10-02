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

#include "UniqueFd.h"

#include "CancellableWait.h"
#include "TcpResolver.h"
#include "TcpSocketBinder.h"

namespace tailgate::linux_frontend::impl
{

TcpStream::TcpStream(TcpResolver& resolver,
                     TcpSocketBinder& binder,
                     const std::string& host,
                     const std::string& service,
                     const std::string& interfaceName,
                     int ioTimeoutSeconds,
                     int connectTimeoutSeconds,
                     std::stop_token cancellation)
    : m_cancellation(cancellation),
      m_readTimeout(std::chrono::seconds(ioTimeoutSeconds)),
      m_writeTimeout(ioTimeoutSeconds)
{
    if (ioTimeoutSeconds <= 0)
    {
        throw std::runtime_error("TCP stream timeout must be positive");
    }
    if (connectTimeoutSeconds <= 0)
    {
        connectTimeoutSeconds = ioTimeoutSeconds;
    }

    ThrowIfCancelled(cancellation);
    const auto results =
        resolver.Resolve(host, service, std::chrono::seconds(connectTimeoutSeconds), cancellation);
    UniqueFd connected;
    for (const auto& entry : results)
    {
        ThrowIfCancelled(cancellation);
        UniqueFd candidate(
            socket(entry.Family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, entry.Protocol));
        if (candidate.Fd < 0)
        {
            continue;
        }
        if (!interfaceName.empty())
        {
            binder.BindToInterface(candidate.Fd, interfaceName);
        }
        bool success = connect(candidate.Fd,
                               reinterpret_cast<const sockaddr*>(&entry.Address),
                               entry.Length) == 0;
        if (!success && errno == EINPROGRESS)
        {
            try
            {
                WaitForSocket(candidate.Fd,
                              POLLOUT,
                              std::chrono::seconds(connectTimeoutSeconds),
                              cancellation);
                int error = 0;
                socklen_t size = sizeof(error);
                success = getsockopt(candidate.Fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 &&
                          error == 0;
            }
            catch (const std::system_error& error)
            {
                if (error.code() != std::errc::timed_out)
                {
                    throw;
                }
            }
        }
        if (success)
        {
            connected = std::move(candidate);
            break;
        }
    }
    m_fd = connected.Fd;

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

    (void)connected.Release();
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
    for (;;)
    {
        ThrowIfCancelled(m_cancellation);
        const ssize_t result = send(m_fd, data, size, MSG_NOSIGNAL);
        if (result >= 0)
        {
            return static_cast<std::size_t>(result);
        }
        if (errno == EINTR)
        {
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            throw std::system_error(errno, std::generic_category());
        }
        if (m_nonBlocking)
        {
            return std::nullopt;
        }
        WaitForSocket(m_fd, POLLOUT, m_writeTimeout, m_cancellation);
    }
}

std::optional<std::vector<std::uint8_t>> TcpStream::TryReadSome(std::size_t maxBytes)
{
    std::vector<std::uint8_t> data(maxBytes);
    for (;;)
    {
        ThrowIfCancelled(m_cancellation);
        const ssize_t result = recv(m_fd, data.data(), data.size(), 0);
        if (result >= 0)
        {
            data.resize(static_cast<std::size_t>(result));
            return data;
        }
        if (errno == EINTR)
        {
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            throw std::system_error(errno, std::generic_category());
        }
        if (m_nonBlocking)
        {
            return std::nullopt;
        }
        WaitForSocket(
            m_fd, POLLIN, m_readTimeout.value_or(std::chrono::seconds::max()), m_cancellation);
    }
}

int TcpStream::NativeHandle() const
{
    return m_fd;
}

void TcpStream::SetReadTimeout(std::optional<std::chrono::seconds> timeout)
{
    m_readTimeout = timeout;
}

void TcpStream::SetNonBlocking(bool enabled)
{
    m_nonBlocking = enabled;
}

} // namespace tailgate::linux_frontend::impl
