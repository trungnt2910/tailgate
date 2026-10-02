#pragma once

#include <functional>
#include <stop_token>

namespace tailgate::uwp::bg::manager
{

// Scoped to one VPN plugin. Windows management operations run after Connect returns,
// while the background dispatcher owns its deferral.
class ProfileRecoveryManager
{
public:
    virtual ~ProfileRecoveryManager() = default;
    virtual void EnterConnect() = 0;
    virtual void LeaveConnect() = 0;
    [[nodiscard]] virtual bool Request() = 0;
    virtual void AttemptTerminated() = 0;
    virtual void RunPending(std::stop_token cancellation) = 0;
    virtual void Disconnecting() = 0;
    virtual void Connected() = 0;

    // Ending the Windows Connect attempt is mandatory even if recovery is declined.
    // The callback belongs to the plugin, which owns the platform channel.
    void FinishFailedConnect(const std::function<void()>& terminate);

    class ConnectScope final
    {
    public:
        explicit ConnectScope(ProfileRecoveryManager& manager) : m_manager(manager)
        {
            m_manager.EnterConnect();
        }

        ~ConnectScope()
        {
            m_manager.LeaveConnect();
        }

        ConnectScope(const ConnectScope&) = delete;
        ConnectScope& operator=(const ConnectScope&) = delete;

    private:
        ProfileRecoveryManager& m_manager;
    };
};

} // namespace tailgate::uwp::bg::manager
