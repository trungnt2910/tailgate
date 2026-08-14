#pragma once

#include <optional>

#include <tailgate/crypto/Crypto.h>

#include "app/model/ControlPlaneState.h"

namespace tailgate::uwp
{

class ControlPlaneController
{
public:
    virtual ~ControlPlaneController() = default;

    [[nodiscard]] virtual const ControlPlaneState& GetState() const noexcept = 0;
    virtual void Logout(std::optional<tailgate::crypto::Bytes32> machineKey,
                        std::optional<tailgate::crypto::Bytes32> nodeKey) = 0;
};

} // namespace tailgate::uwp
