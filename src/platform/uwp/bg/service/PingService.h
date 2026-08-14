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

#include "common/UwpAppServiceProtocol.h"
#include "common/UwpFormat.h"

#include "manager/DataPlaneManager.h"
#include "service/ServiceBase.h"

namespace tailgate::uwp::bg::service
{

class PingService final : public ServiceBase
{
public:
    explicit PingService(manager::DataPlaneManager& dataPlaneManager);

    void Start(SessionGeneration generation) override;
    void Stop() override;
    void Reset() override;
    void Encapsulate(EncapsulationContext& context) override;
    void Decapsulate(DecapsulationContext& context) override;
    void FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput) override;

    void Handle(const tailgate::net::packet::Ipv4UdpDatagram& datagram,
                const app_service::PingRequest& request,
                const tailgate::types::netmap::NetworkConfig& config,
                tailgate::disco::Disco* disco,
                const std::string& relayName,
                std::vector<std::uint8_t>& relayOutput,
                std::vector<std::vector<std::uint8_t>>& appResponses);

    void Complete(const tailgate::disco::Disco::Message& message,
                  const tailgate::hosted::PeerPacket& packet);

private:
    struct PendingPing
    {
        std::uint64_t Sequence = 0;
        tailgate::disco::Disco::TransactionId Transaction{};
        std::chrono::steady_clock::time_point Started{};
        std::string PeerName;
        std::string Relay;
        std::uint32_t AppAddress = 0;
        std::uint16_t AppPort = 0;
    };

    std::vector<PendingPing> m_pending;
    std::vector<std::vector<std::uint8_t>> m_responses;
    tailgate::base::Logger m_logger{"uwp-app-ping"};
};

} // namespace tailgate::uwp::bg::service
