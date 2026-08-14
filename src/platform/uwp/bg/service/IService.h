#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <tailgate/disco/Disco.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/types/netmap/NetworkMap.h>
#include <tailgate/wgengine/wireguard/Router.h>

#include "manager/SessionManager.h"

namespace tailgate::uwp::bg::service
{

using manager::SessionGeneration;

struct EncapsulationContext
{
    const std::vector<std::uint8_t>& Original;
    const tailgate::types::netmap::NetworkConfig& Config;
    tailgate::disco::Disco* Disco = nullptr;
    tailgate::wgengine::wireguard::WireGuardRouter* Router = nullptr;
    const std::string& ExitNode;
    const std::string& RelayName;
    std::vector<std::uint8_t>& RemoteOutput;
    bool ReconnectRequested = false;
};

struct DecapsulationContext
{
    const tailgate::hosted::Frame& Message;
    tailgate::types::netmap::NetworkConfig& Config;
    tailgate::disco::Disco* Disco = nullptr;
    tailgate::wgengine::wireguard::WireGuardRouter* Router = nullptr;
    const tailgate::crypto::Bytes32& NodePrivateKey;
    const tailgate::crypto::Bytes32& NodePublicKey;
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
