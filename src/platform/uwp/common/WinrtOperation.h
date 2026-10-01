#pragma once

#include <chrono>
#include <optional>
#include <stop_token>
#include <system_error>

#include <winrt/Windows.Foundation.h>

namespace tailgate::uwp
{

template <typename T>
auto AwaitOperation(const T& operation,
                    std::optional<std::chrono::seconds> timeout,
                    std::stop_token cancellation)
{
    const std::stop_callback stopped(cancellation,
                                     [&]() noexcept
                                     {
                                         try
                                         {
                                             operation.Cancel();
                                         }
                                         catch (...)
                                         { /* The operation may already have completed or closed. */
                                         }
                                     });
    if (!timeout)
    {
        return operation.get();
    }
    if (operation.wait_for(*timeout) == winrt::Windows::Foundation::AsyncStatus::Started)
    {
        operation.Cancel();
        throw std::system_error(std::make_error_code(std::errc::timed_out));
    }
    return operation.GetResults();
}

} // namespace tailgate::uwp
