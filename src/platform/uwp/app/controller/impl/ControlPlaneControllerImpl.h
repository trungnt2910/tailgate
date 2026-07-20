#pragma once

#include <tailgate/Logger.h>

#include "common/UwpFireAndForget.h"
#include "common/UwpFormat.h"

#include "app/controller/ControlPlaneController.h"

namespace tailgate::uwp
{

class ControlPlaneControllerImpl final : public ControlPlaneController
{
public:
    [[nodiscard]] const ControlPlaneState& GetState() const noexcept override;
    void Logout(std::optional<protocol::Bytes32> machineKey,
                std::optional<protocol::Bytes32> nodeKey) override;

private:
    FireAndForget LogoutInBackground(std::optional<protocol::Bytes32> machineKey,
                                     std::optional<protocol::Bytes32> nodeKey);

    ControlPlaneState m_state;
    Logger m_logger{"uwp-control-plane-ctrl"};
};

} // namespace tailgate::uwp
