#pragma once

#include <memory>

#include <tailgate/base/Logger.h>

#include "common/AuthorizationState.h"
#include "common/UwpFireAndForget.h"
#include "common/UwpFormat.h"

#include "app/controller/InteractiveAuthorizationController.h"

namespace tailgate::uwp
{

class InteractiveAuthorizationControllerImpl final : public InteractiveAuthorizationController
{
public:
    ~InteractiveAuthorizationControllerImpl() override;

    [[nodiscard]] const InteractiveAuthorizationState& GetState() const noexcept override;
    void Listen(const winrt::hstring& profileId) override;
    void Stop() override;
    void Cancel() override;

private:
    void StartListening(const winrt::hstring& profileId);
    FireAndForget Monitor(AuthorizationStateReceiver* receiver);
    void Publish(const ConnectionMessage& message);

    std::unique_ptr<AuthorizationStateReceiver> m_receiver;
    winrt::hstring m_pendingProfileId;
    bool m_stopRequested = false;
    InteractiveAuthorizationState m_state;
    tailgate::base::Logger m_logger{"uwp-interactive-auth-ctrl"};
};

} // namespace tailgate::uwp
