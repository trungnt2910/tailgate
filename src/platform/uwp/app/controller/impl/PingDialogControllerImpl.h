#pragma once

#include <tailgate/Logger.h>

#include "common/UwpFormat.h"

#include "app/controller/ContentDialogController.h"
#include "app/controller/PingController.h"
#include "app/controller/PingDialogController.h"
#include "app/model/PingDialogState.h"

namespace tailgate::uwp
{

class PingDialogControllerImpl final : public PingDialogController
{
public:
    PingDialogControllerImpl(ContentDialogController& dialogController,
                             PingController& pingController);

    [[nodiscard]] const PingDialogState& GetState() const noexcept override;
    void Show(const winrt::hstring& deviceName,
              const winrt::hstring& address,
              const winrt::hstring& selfAddress) override;
    void Hide() override;
    void OnClosed() override;

private:
    ContentDialogController& m_dialogController;
    PingController& m_pingController;
    PingDialogState m_state;
    Logger m_logger{"uwp-ping-dialog-ctrl"};
};

} // namespace tailgate::uwp
