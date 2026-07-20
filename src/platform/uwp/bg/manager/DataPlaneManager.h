#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "manager/SessionManager.h"

namespace tailgate::uwp::bg::service
{

class IService;
struct EncapsulationContext;
struct DecapsulationContext;

} // namespace tailgate::uwp::bg::service

namespace tailgate::uwp::bg::manager
{

struct DataPlaneProbe
{
    std::string ConnectAddress;
    std::string ValidationHost;
    std::string Service;
    bool UsingCachedEndpoint = false;
};

class DataPlaneManager
{
public:
    virtual ~DataPlaneManager() = default;

    virtual void Register(service::IService& service) = 0;
    virtual void Start(SessionGeneration generation) = 0;
    [[nodiscard]] virtual DataPlaneProbe
    Probe(const std::string& server, const std::string& host, const std::string& service) = 0;
    virtual void RememberProbe(const std::string& server, const DataPlaneProbe& probe) = 0;
    virtual void InvalidateProbe(const std::string& server) = 0;
    virtual void Connect() = 0;
    virtual void Stop() = 0;
    virtual void Reset() = 0;
    virtual void Encapsulate(service::EncapsulationContext& context) = 0;
    virtual void Decapsulate(service::DecapsulationContext& context) = 0;
    virtual void FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput) = 0;

    [[nodiscard]] virtual std::size_t ServiceCount() const = 0;
};

} // namespace tailgate::uwp::bg::manager
