#include "app/controller/impl/SetOptionsControllerImpl.h"

#include <optional>

#include "app/controller/ExitNodeController.h"
#include "app/controller/SessionController.h"
#include "app/controller/SettingsController.h"

namespace tailgate::uwp
{

SetOptionsControllerImpl::SetOptionsControllerImpl(ExitNodeController& exitNodeController,
                                                   SessionController& sessionController,
                                                   SettingsController& settingsController)
    : m_exitNodeController(exitNodeController),
      m_sessionController(sessionController),
      m_settingsController(settingsController)
{
}

const SetOptionsState& SetOptionsControllerImpl::GetState() const noexcept
{
    return m_state;
}

void SetOptionsControllerImpl::Apply(const tailgate::cli::SetOptions& options)
{
    const SessionState& session = m_sessionController.GetState();
    if (session.ConnectionOperationActive())
    {
        m_logger.LogDebug("ignoring set command: a connection operation is already in progress");
        return;
    }
    m_settingsController.Reload();
    const std::optional<ConnectionSettingsSnapshot> rollbackSettings =
        session.Connected() ? std::optional(m_settingsController.GetState().ConnectionSettings())
                            : std::nullopt;
    bool restartConnectedProfile = false;
    if (options.TailgateUrl)
    {
        m_settingsController.SetTailgateServer(winrt::to_hstring(*options.TailgateUrl));
        restartConnectedProfile = true;
    }
    if (options.Hostname)
    {
        m_settingsController.SetHostname(winrt::to_hstring(*options.Hostname));
    }
    if (options.ExitNode)
    {
        const winrt::hstring requested = winrt::to_hstring(*options.ExitNode);
        if (!session.Connected() || restartConnectedProfile)
        {
            m_exitNodeController.SetNodeForNextConnection(requested);
        }
        else
        {
            m_exitNodeController.SetNode(requested);
        }
    }
    if (restartConnectedProfile && session.Connected())
    {
        m_settingsController.Reload();
        m_sessionController.Connect(
            m_settingsController.GetState().TailgateServer(), L"", false, true, rollbackSettings);
    }
}

} // namespace tailgate::uwp
