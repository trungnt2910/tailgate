#pragma once

#include <tailgate/base/Logger.h>
#include <tailgate/control/client/Session.h>

#include "common/UwpFireAndForget.h"
#include "common/UwpFormat.h"

#include "app/controller/ControlPlaneController.h"

namespace tailgate::uwp
{

class TcpSocketFactory;

class ControlPlaneControllerImpl final : public ControlPlaneController
{
public:
    ControlPlaneControllerImpl(tailgate::control::client::SessionFactory& controlSessionFactory,
                               TcpSocketFactory& socketFactory) noexcept;

    [[nodiscard]] const ControlPlaneState& GetState() const noexcept override;
    void Logout(std::optional<tailgate::crypto::Bytes32> machineKey,
                std::optional<tailgate::crypto::Bytes32> nodeKey) override;

private:
    FireAndForget LogoutInBackground(std::optional<tailgate::crypto::Bytes32> machineKey,
                                     std::optional<tailgate::crypto::Bytes32> nodeKey);

    tailgate::control::client::SessionFactory& m_controlSessionFactory;
    TcpSocketFactory& m_socketFactory;
    ControlPlaneState m_state;
    tailgate::base::Logger m_logger{"uwp-control-plane-ctrl"};
};

} // namespace tailgate::uwp
