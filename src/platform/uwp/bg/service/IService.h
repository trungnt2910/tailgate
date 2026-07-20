#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <tailgate/control/NetworkMap.h>
#include <tailgate/protocol/Disco.h>
#include <tailgate/protocol/WireGuardRouter.h>
#include <tailgate/relay/RelayProtocol.h>

#include "manager/SessionManager.h"

namespace tailgate::uwp::bg::service
{

using manager::SessionGeneration;

struct EncapsulationContext
{
    const std::vector<std::uint8_t>& Original;
    const control::NetworkConfig& Config;
    protocol::Disco* Disco = nullptr;
    protocol::WireGuardRouter* Router = nullptr;
    const std::string& ExitNode;
    const std::string& RelayName;
    std::vector<std::uint8_t>& RemoteOutput;
    bool ReconnectRequested = false;
};

struct DecapsulationContext
{
    const relay::Frame& Message;
    control::NetworkConfig& Config;
    protocol::Disco* Disco = nullptr;
    protocol::WireGuardRouter* Router = nullptr;
    const protocol::Bytes32& NodePrivateKey;
    const protocol::Bytes32& NodePublicKey;
    const std::string& ExitNode;
    std::vector<std::vector<std::uint8_t>>& LocalOutput;
    std::vector<std::uint8_t>& RemoteOutput;
};

class IService
{
public:
    virtual ~IService() = default;

    virtual void Start(SessionGeneration generation) = 0;
    virtual void Stop() = 0;
    virtual void Reset() = 0;
    virtual void Encapsulate(EncapsulationContext& context) = 0;
    virtual void Decapsulate(DecapsulationContext& context) = 0;
    virtual void FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput) = 0;
};

} // namespace tailgate::uwp::bg::service
