#pragma once

#include <tailgate/Logger.h>

#include "manager/DataPlaneManager.h"
#include "manager/SessionManager.h"
#include "service/ServiceBase.h"

namespace tailgate::uwp::bg::service
{

class PingService;

class NetworkService final : public ServiceBase
{
public:
    NetworkService(manager::DataPlaneManager& dataPlaneManager,
                   manager::SessionManager& sessionManager,
                   PingService& pingService);

    void Start(SessionGeneration generation) override;
    void Stop() override;
    void Reset() override;
    void Encapsulate(EncapsulationContext& context) override;
    void Decapsulate(DecapsulationContext& context) override;
    void FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput) override;

private:
    void ProcessDiscoPacket(const relay::PeerPacket& packet, DecapsulationContext& context);

    PingService& m_pingService;
    manager::SessionManager& m_sessionManager;
    Logger m_logger{"uwp-network-service"};
};

} // namespace tailgate::uwp::bg::service
