#include "ProcessWait.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <limits>
#include <system_error>

#include <poll.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "UniqueFd.h"

namespace tailgate::linux_frontend
{

bool WaitForProcessExit(pid_t processId, std::chrono::milliseconds timeout)
{
    UniqueFd process(static_cast<int>(syscall(SYS_pidfd_open, processId, 0)));
    if (process.Fd < 0)
    {
        if (errno == ESRCH)
        {
            return true;
        }
        throw std::system_error(
            errno, std::generic_category(), "failed to create process exit notification");
    }
    if (timeout <= std::chrono::milliseconds::zero())
    {
        return false;
    }
    const auto bounded = std::min<std::int64_t>(timeout.count(), std::numeric_limits<int>::max());
    pollfd descriptor{.fd = process.Fd, .events = POLLIN, .revents = 0};
    int result = 0;
    do
    {
        result = poll(&descriptor, 1, static_cast<int>(bounded));
    } while (result < 0 && errno == EINTR);
    if (result < 0)
    {
        throw std::system_error(errno, std::generic_category(), "failed to wait for process exit");
    }
    return result > 0;
}

} // namespace tailgate::linux_frontend
