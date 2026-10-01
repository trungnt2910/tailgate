#include "CancellableWait.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <system_error>

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "UniqueFd.h"

namespace tailgate::linux_frontend::impl
{

void ThrowIfCancelled(std::stop_token cancellation)
{
    if (cancellation.stop_requested())
    {
        throw std::system_error(std::make_error_code(std::errc::operation_canceled));
    }
}

void WaitForSocket(int descriptor,
                   short events,
                   std::chrono::seconds timeout,
                   std::stop_token cancellation)
{
    ThrowIfCancelled(cancellation);
    UniqueFd wake(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    if (wake.Fd < 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    const std::stop_callback stopped(cancellation,
                                     [&]() noexcept
                                     {
                                         const std::uint64_t value = 1;
                                         while (write(wake.Fd, &value, sizeof(value)) < 0 &&
                                                errno == EINTR)
                                         {
                                         }
                                     });
    std::array<pollfd, 2> descriptors{{
        {.fd = descriptor, .events = events, .revents = 0},
        {.fd = wake.Fd, .events = POLLIN, .revents = 0},
    }};
    const auto deadline = timeout == std::chrono::seconds::max()
                              ? std::chrono::steady_clock::time_point::max()
                              : std::chrono::steady_clock::now() + timeout;
    for (;;)
    {
        const auto remaining = deadline - std::chrono::steady_clock::now();
        const auto milliseconds = std::chrono::ceil<std::chrono::milliseconds>(remaining).count();
        const int result = poll(descriptors.data(),
                                descriptors.size(),
                                timeout == std::chrono::seconds::max()
                                    ? -1
                                    : static_cast<int>(std::max<std::int64_t>(0, milliseconds)));
        ThrowIfCancelled(cancellation);
        if (result > 0)
        {
            return;
        }
        if (result == 0)
        {
            throw std::system_error(std::make_error_code(std::errc::timed_out));
        }
        if (errno != EINTR)
        {
            throw std::system_error(errno, std::generic_category());
        }
    }
}

} // namespace tailgate::linux_frontend::impl
