#pragma once

#include <chrono>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>

#include <tailgate/control/ControlClient.h>
#include <tailgate/control/NetworkMap.h>
#include <tailgate/protocol/Crypto.h>

#include "manager/SessionManager.h"

namespace tailgate::uwp::bg::manager
{

using NetworkMapHandler = std::function<void(control::NetworkConfig)>;

class ControlIdentityChangedError final : public std::runtime_error
{
public:
    ControlIdentityChangedError()
        : std::runtime_error("Control stream changed the UWP node identity.")
    {
    }
};

class ControlPlaneManager
{
public:
    virtual ~ControlPlaneManager() = default;

    virtual void Start(SessionGeneration generation) = 0;
    virtual void LoadIdentity(bool registered) = 0;
    [[nodiscard]] virtual control::RegistrationResult Connect(const std::string& authKey) = 0;
    virtual void StartMaintenance(NetworkMapHandler networkMapHandler) = 0;
    virtual void StopMaintenance() = 0;
    virtual void RequestStop() = 0;
    virtual void Stop() = 0;
    virtual void Reset() = 0;

    [[nodiscard]] virtual bool IsStopping() const = 0;
    [[nodiscard]] virtual const protocol::Bytes32& NodePrivateKey() const = 0;
    [[nodiscard]] virtual const protocol::Bytes32& NodePublicKey() const = 0;
    [[nodiscard]] virtual const protocol::Bytes32& DiscoPrivateKey() const = 0;
};

} // namespace tailgate::uwp::bg::manager
