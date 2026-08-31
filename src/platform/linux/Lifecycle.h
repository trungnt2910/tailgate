#pragma once

#include <chrono>
#include <csignal>

namespace tailgate::linux_frontend
{

class Lifecycle final
{
public:
    Lifecycle() = delete;

    static void Initialize();
    static void RequestStop() noexcept;
    static void RequestReload() noexcept;
    [[nodiscard]] static bool WaitForChange(std::chrono::milliseconds timeout);

    [[nodiscard]] static bool Stopping() noexcept;
    [[nodiscard]] static bool Reloading() noexcept;
    static void ClearStop() noexcept;
    static void ClearReload() noexcept;

    static void BeginStartup(std::sig_atomic_t daemonPid) noexcept;
    static void EndStartup() noexcept;
    static void InterruptStartup() noexcept;
    [[nodiscard]] static bool StartupInterrupted() noexcept;

private:
    static volatile std::sig_atomic_t m_stopRequested;
    static volatile std::sig_atomic_t m_reloadRequested;
    static volatile std::sig_atomic_t m_startupInterrupted;
    static volatile std::sig_atomic_t m_startupDaemonPid;
};

} // namespace tailgate::linux_frontend
