#pragma once

#include <tailgate/hosted/Dns.h>

#include "manager/DataPlaneManager.h"
#include "service/ServiceBase.h"

namespace tailgate::uwp::bg::service
{

class HostedDnsService final : public ServiceBase
{
public:
    HostedDnsService(manager::DataPlaneManager& dataPlaneManager, tailgate::hosted::Dns& dns);

    void Start(SessionGeneration generation) override;
    void Stop() override;
    void Reset() override;
    void Encapsulate(EncapsulationContext& context) override;
    void Decapsulate(DecapsulationContext& context) override;
    void FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput) override;

private:
    tailgate::hosted::Dns& m_dns;
};

} // namespace tailgate::uwp::bg::service
