#pragma once

#include <optional>

#include <tailgate/protocol/Crypto.h>

#include "app/model/ControlPlaneState.h"

namespace tailgate::uwp
{

class ControlPlaneController
{
public:
    virtual ~ControlPlaneController() = default;

    [[nodiscard]] virtual const ControlPlaneState& GetState() const noexcept = 0;
    virtual void Logout(std::optional<protocol::Bytes32> machineKey,
                        std::optional<protocol::Bytes32> nodeKey) = 0;
};

} // namespace tailgate::uwp
