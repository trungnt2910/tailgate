#include "FdStream.h"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <stdexcept>

#include <poll.h>
#include <unistd.h>

namespace tailgate::linux_frontend
{

FdStream::FdStream(int fd) : m_fd(fd)
{
    if (fd < 0)
    {
        throw std::invalid_argument("file descriptor stream requires a valid descriptor");
    }
}

std::optional<std::size_t> FdStream::TryWriteSome(const std::uint8_t* data, std::size_t size)
{
    while (true)
    {
        const ssize_t result = write(m_fd, data, size);
        if (result < 0 && errno == EINTR)
        {
            continue;
        }
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            return std::nullopt;
        }
        if (result < 0)
        {
            throw std::runtime_error("descriptor write failed: " +
                                     std::string(std::strerror(errno)));
        }
        return static_cast<std::size_t>(result);
    }
}

std::optional<std::vector<std::uint8_t>> FdStream::TryReadSome(std::size_t maxBytes)
{
    while (m_readDeadline)
    {
        const auto remaining = *m_readDeadline - std::chrono::steady_clock::now();
        if (remaining <= std::chrono::steady_clock::duration::zero())
        {
            throw std::runtime_error("descriptor read timed out");
        }
        const auto rounded = std::chrono::ceil<std::chrono::milliseconds>(remaining).count();
        pollfd descriptor{.fd = m_fd, .events = POLLIN, .revents = 0};
        const int result = poll(&descriptor, 1, static_cast<int>(rounded));
        if (result > 0)
        {
            break;
        }
        if (result == 0)
        {
            throw std::runtime_error("descriptor read timed out");
        }
        if (errno != EINTR)
        {
            throw std::runtime_error("descriptor poll failed: " +
                                     std::string(std::strerror(errno)));
        }
    }
    std::vector<std::uint8_t> data(maxBytes);
    while (true)
    {
        const ssize_t result = read(m_fd, data.data(), data.size());
        if (result < 0 && errno == EINTR)
        {
            continue;
        }
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            return std::nullopt;
        }
        if (result < 0)
        {
            throw std::runtime_error("descriptor read failed: " +
                                     std::string(std::strerror(errno)));
        }
        data.resize(static_cast<std::size_t>(result));
        return data;
    }
}

void FdStream::SetReadTimeout(std::chrono::milliseconds timeout)
{
    m_readDeadline = std::chrono::steady_clock::now() + timeout;
}

void FdStream::ClearReadTimeout()
{
    m_readDeadline.reset();
}

} // namespace tailgate::linux_frontend
