#pragma once

#include <memory>

#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"

#include "common/UwpFireAndForget.h"

#include "app/controller/ExitNodeController.h"
#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

class SessionController;
class SettingsController;
struct ExitNodeChangeState;

class ExitNodeControllerImpl final : public ExitNodeController
{
public:
    ExitNodeControllerImpl(SessionController& sessionController,
                           SettingsController& settingsController);

    [[nodiscard]] const ExitNodeState& GetState() const noexcept override;
    void Reload() override;
    void SetNode(const winrt::hstring& nodeName) override;
    void SetNodeForNextConnection(const winrt::hstring& nodeName) override;
    void SetEnabled(bool enabled) override;

private:
    [[nodiscard]] winrt::hstring ValidateNode(const winrt::hstring& nodeName) const;
    void StartChange(winrt::hstring nodeName, bool preserveSelection);
    FireAndForget
    ChangeAsync(winrt::hstring nodeName, bool preserveSelection, winrt::hstring selfAddress);
    foundation::IAsyncAction RequestChangeAsync(winrt::hstring nodeName,
                                                bool preserveSelection,
                                                winrt::hstring selfAddress,
                                                std::shared_ptr<ExitNodeChangeState> state);

    SessionController& m_sessionController;
    SettingsController& m_settingsController;
    ExitNodeState m_state;
    StateEventRegistration m_settingsRegistration;
    tailgate::base::Logger m_logger{"uwp-exit-node-ctrl"};
};

} // namespace tailgate::uwp
