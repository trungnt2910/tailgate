#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <tailgate/hosted/Client.h>

#include "manager/SessionManager.h"

namespace tailgate::uwp::bg::service
{

using manager::SessionGeneration;

struct EncapsulationContext
{
    const std::vector<std::uint8_t>& Original;
    tailgate::hosted::Client& Client;
    const std::string& RelayName;
    std::vector<std::uint8_t>& RemoteOutput;
    bool ReconnectRequested = false;
};

struct DecapsulationContext
{
    const tailgate::hosted::Frame& Message;
    tailgate::hosted::Client& Client;
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
