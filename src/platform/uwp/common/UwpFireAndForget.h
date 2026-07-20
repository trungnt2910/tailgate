#pragma once

#include <coroutine>

#include <winrt/base.h>

#include <tailgate/Logger.h>

#include "common/UwpFormat.h"

namespace tailgate::uwp
{

// C++/WinRT's fire_and_forget terminates on an unhandled exception. Keep that behavior while
// recording the exception in Tailgate's log first.
struct FireAndForget
{
    struct promise_type
    {
        [[nodiscard]] FireAndForget get_return_object() const noexcept
        {
            return {};
        }

        [[nodiscard]] std::suspend_never initial_suspend() const noexcept
        {
            return {};
        }

        [[nodiscard]] std::suspend_never final_suspend() const noexcept
        {
            return {};
        }

        void return_void() const noexcept
        {
        }

        [[noreturn]] void unhandled_exception() const noexcept
        {
            try
            {
                m_logger.LogError("unhandled fire-and-forget exception: {}", winrt::to_message());
            }
            catch (...)
            {
                // Logging must not replace the original exception or prevent fail-fast.
            }
            winrt::terminate();
        }

    private:
        Logger m_logger{"uwp-fire-and-forget"};
    };
};

} // namespace tailgate::uwp
