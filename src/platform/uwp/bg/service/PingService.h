#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include <tailgate/Logger.h>

#include "common/UwpFormat.h"
#include <tailgate/control/NetworkMap.h>
#include <tailgate/network/Ipv4.h>
#include <tailgate/protocol/Disco.h>
#include <tailgate/relay/RelayProtocol.h>

#include "common/UwpAppServiceProtocol.h"

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

    void Handle(const network::Ipv4UdpDatagram& datagram,
                const app_service::PingRequest& request,
                const control::NetworkConfig& config,
                protocol::Disco* disco,
                const std::string& relayName,
                std::vector<std::uint8_t>& relayOutput,
                std::vector<std::vector<std::uint8_t>>& appResponses);

    void Complete(const protocol::Disco::Message& message, const relay::PeerPacket& packet);

private:
    struct PendingPing
    {
        std::uint64_t Sequence = 0;
        protocol::Disco::TransactionId Transaction{};
        std::chrono::steady_clock::time_point Started{};
        std::string PeerName;
        std::string Relay;
        std::uint32_t AppAddress = 0;
        std::uint16_t AppPort = 0;
    };

    std::vector<PendingPing> m_pending;
    std::vector<std::vector<std::uint8_t>> m_responses;
    Logger m_logger{"uwp-app-ping"};
};

} // namespace tailgate::uwp::bg::service
