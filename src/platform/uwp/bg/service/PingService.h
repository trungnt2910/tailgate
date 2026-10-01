#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include <tailgate/base/Logger.h>
#include <tailgate/disco/Disco.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/netmap/NetworkMap.h>
#include <tailgate/wgengine/ping/Tracker.h>

#include "common/UwpAppServiceProtocol.h"
#include "common/UwpFormat.h"

#include "manager/DataPlaneManager.h"
#include "service/ServiceBase.h"

namespace tailgate::uwp::bg::service
{

class PingService final : public ServiceBase
{
public:
    PingService(manager::DataPlaneManager& dataPlaneManager, tailgate::base::TimeProvider& time);

    void Start(SessionGeneration generation) override;
    void Stop() override;
    void Reset() override;
    void Encapsulate(EncapsulationContext& context) override;
    void FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput) override;
    [[nodiscard]] bool HasLocalOutput() const override;

    void Complete(const tailgate::wgengine::ping::Result& result,
                  bool direct,
                  const std::string& endpoint);
    [[nodiscard]] std::optional<tailgate::base::TimeProvider::TimePoint>
    NextDeadline() const override;

private:
    struct PendingResponse
    {
        std::uint64_t RequestId = 0;
        std::uint64_t Sequence = 0;
        std::uint32_t AppAddress = 0;
        std::uint16_t AppPort = 0;
        bool Hosted = false;
        tailgate::base::TimeProvider::TimePoint Deadline{};
    };

    std::vector<PendingResponse> m_pending;
    std::vector<std::vector<std::uint8_t>> m_responses;
    tailgate::base::TimeProvider& m_time;
    std::uint64_t m_nextRequestId = 1;
    tailgate::base::Logger m_logger{"uwp-app-ping"};
};

} // namespace tailgate::uwp::bg::service
