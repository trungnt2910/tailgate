#pragma once

#include <tailgate/base/Logger.h>

#include "manager/DataPlaneManager.h"
#include "service/ServiceBase.h"

namespace tailgate::uwp::bg::service
{

class HostedDnsService final : public ServiceBase
{
public:
    explicit HostedDnsService(manager::DataPlaneManager& dataPlaneManager);

    void Start(SessionGeneration generation) override;
    void Stop() override;
    void Reset() override;
    void Encapsulate(EncapsulationContext& context) override;
    void Decapsulate(DecapsulationContext& context) override;
    void FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput) override;

private:
    tailgate::base::Logger m_logger{"uwp-hosted-dns-service"};
};

} // namespace tailgate::uwp::bg::service
