#include "Lifecycle.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <limits>
#include <system_error>

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace tailgate::linux_frontend
{

namespace
{

volatile std::sig_atomic_t WakeDescriptor = -1;

void Wake() noexcept
{
    if (WakeDescriptor < 0)
    {
        return;
    }
    constexpr std::uint64_t Increment = 1;
    const ssize_t ignored = write(WakeDescriptor, &Increment, sizeof(Increment));
    (void)ignored;
}

void DrainWake() noexcept
{
    std::uint64_t value = 0;
    while (read(WakeDescriptor, &value, sizeof(value)) == sizeof(value))
    {
    }
}

} // namespace

volatile std::sig_atomic_t Lifecycle::m_stopRequested = 0;
volatile std::sig_atomic_t Lifecycle::m_reloadRequested = 0;
volatile std::sig_atomic_t Lifecycle::m_startupInterrupted = 0;
volatile std::sig_atomic_t Lifecycle::m_startupDaemonPid = 0;

void Lifecycle::Initialize()
{
    if (WakeDescriptor >= 0)
    {
        return;
    }
    WakeDescriptor = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (WakeDescriptor < 0)
    {
        throw std::system_error(
            errno, std::generic_category(), "failed to initialize lifecycle wake descriptor");
    }
}

void Lifecycle::RequestStop() noexcept
{
    m_stopRequested = 1;
    Wake();
}

void Lifecycle::RequestReload() noexcept
{
    m_reloadRequested = 1;
    Wake();
}

bool Lifecycle::WaitForChange(std::chrono::milliseconds timeout)
{
    Initialize();
    if (Stopping() || Reloading())
    {
        return false;
    }
    if (timeout <= std::chrono::milliseconds::zero())
    {
        return true;
    }
    DrainWake();
    if (Stopping() || Reloading())
    {
        return false;
    }
    const auto bounded = std::min<std::int64_t>(timeout.count(), std::numeric_limits<int>::max());
    pollfd descriptor{.fd = WakeDescriptor, .events = POLLIN, .revents = 0};
    int result = 0;
    do
    {
        result = poll(&descriptor, 1, static_cast<int>(bounded));
    } while (result < 0 && errno == EINTR && !Stopping() && !Reloading());
    if (result < 0 && errno == EINTR && (Stopping() || Reloading()))
    {
        return false;
    }
    if (result < 0)
    {
        throw std::system_error(errno, std::generic_category(), "lifecycle wait failed");
    }
    if (result > 0)
    {
        DrainWake();
    }
    return !Stopping() && !Reloading();
}

bool Lifecycle::Stopping() noexcept
{
    return m_stopRequested != 0;
}

bool Lifecycle::Reloading() noexcept
{
    return m_reloadRequested != 0;
}

void Lifecycle::ClearStop() noexcept
{
    m_stopRequested = 0;
}

void Lifecycle::ClearReload() noexcept
{
    m_reloadRequested = 0;
}

void Lifecycle::BeginStartup(std::sig_atomic_t daemonPid) noexcept
{
    m_startupInterrupted = 0;
    m_startupDaemonPid = daemonPid;
}

void Lifecycle::EndStartup() noexcept
{
    m_startupDaemonPid = 0;
}

void Lifecycle::InterruptStartup() noexcept
{
    m_startupInterrupted = 1;
    if (m_startupDaemonPid > 0)
    {
        kill(static_cast<pid_t>(m_startupDaemonPid), SIGTERM);
    }
}

bool Lifecycle::StartupInterrupted() noexcept
{
    return m_startupInterrupted != 0;
}

} // namespace tailgate::linux_frontend
