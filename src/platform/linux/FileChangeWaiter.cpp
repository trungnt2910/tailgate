#include "FileChangeWaiter.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <system_error>

#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "Lifecycle.h"

namespace tailgate::linux_frontend
{
namespace
{

constexpr std::uint32_t WatchedEvents = IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVED_TO;
constexpr std::size_t NotificationBufferSize = 4096;

} // namespace

FileChangeWaiter::FileChangeWaiter(const std::string& directory)
    : m_descriptor(inotify_init1(IN_CLOEXEC | IN_NONBLOCK))
{
    if (m_descriptor.Fd < 0)
    {
        throw std::system_error(
            errno, std::generic_category(), "failed to initialize file change notifications");
    }
    if (inotify_add_watch(m_descriptor.Fd, directory.c_str(), WatchedEvents) < 0)
    {
        throw std::system_error(
            errno, std::generic_category(), "failed to watch state directory changes");
    }
}

int FileChangeWaiter::Descriptor() const noexcept
{
    return m_descriptor.Fd;
}

bool FileChangeWaiter::TakeChange(const std::string& name)
{
    alignas(inotify_event) std::array<std::byte, NotificationBufferSize> buffer{};
    bool matched = false;
    while (true)
    {
        const ssize_t count = read(m_descriptor.Fd, buffer.data(), buffer.size());
        if (count < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return matched;
            }
            if (errno == EINTR)
            {
                continue;
            }
            throw std::system_error(
                errno, std::generic_category(), "failed to read file change notification");
        }
        if (count == 0)
        {
            return matched;
        }
        std::size_t offset = 0;
        while (offset < static_cast<std::size_t>(count))
        {
            const auto* event = reinterpret_cast<const inotify_event*>(buffer.data() + offset);
            if (event->len != 0 && name == event->name)
            {
                matched = true;
            }
            offset += sizeof(inotify_event) + event->len;
        }
    }
}

bool FileChangeWaiter::WaitForChange(const std::string& name,
                                     std::chrono::milliseconds timeout,
                                     bool interruptible)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (true)
    {
        if (interruptible && Lifecycle::Stopping())
        {
            return false;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining <= std::chrono::milliseconds::zero())
        {
            return false;
        }
        const auto bounded =
            std::min<std::int64_t>(remaining.count(), std::numeric_limits<int>::max());
        pollfd descriptor{.fd = m_descriptor.Fd, .events = POLLIN, .revents = 0};
        const int result = poll(&descriptor, 1, static_cast<int>(bounded));
        if (result == 0)
        {
            return false;
        }
        if (result < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            throw std::system_error(
                errno, std::generic_category(), "failed to wait for file change notification");
        }
        if (TakeChange(name))
        {
            return true;
        }
    }
}

} // namespace tailgate::linux_frontend
