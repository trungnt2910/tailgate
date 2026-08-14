#pragma once

#include <chrono>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>

#include <tailgate/control/client/ControlClient.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/types/netmap/NetworkMap.h>

#include "manager/SessionManager.h"

namespace tailgate::uwp::bg::manager
{

using NetworkMapHandler = std::function<void(tailgate::types::netmap::NetworkConfig)>;

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
    [[nodiscard]] virtual tailgate::control::client::RegistrationResult
    Connect(const std::string& authKey) = 0;
    virtual void StartMaintenance(NetworkMapHandler networkMapHandler) = 0;
    virtual void StopMaintenance() = 0;
    virtual void RequestStop() = 0;
    virtual void Stop() = 0;
    virtual void Reset() = 0;

    [[nodiscard]] virtual bool IsStopping() const = 0;
    [[nodiscard]] virtual const tailgate::crypto::Bytes32& NodePrivateKey() const = 0;
    [[nodiscard]] virtual const tailgate::crypto::Bytes32& NodePublicKey() const = 0;
    [[nodiscard]] virtual const tailgate::crypto::Bytes32& DiscoPrivateKey() const = 0;
};

} // namespace tailgate::uwp::bg::manager
