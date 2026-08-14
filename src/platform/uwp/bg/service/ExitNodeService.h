#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/base/Logger.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/netmap/NetworkMap.h>

#include "common/UwpAppServiceProtocol.h"
#include "common/UwpFormat.h"

#include "manager/DataPlaneManager.h"
#include "service/ServiceBase.h"

namespace tailgate::uwp::bg::service
{

enum class ExitNodeAction
{
    Handled,
    Reconnect,
};

class ExitNodeService final : public ServiceBase
{
public:
    explicit ExitNodeService(manager::DataPlaneManager& dataPlaneManager);

    void Start(SessionGeneration generation) override;
    void Stop() override;
    void Reset() override;
    void Encapsulate(EncapsulationContext& context) override;
    void Decapsulate(DecapsulationContext& context) override;
    void FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput) override;
    void LoadPending(const tailgate::types::netmap::NetworkConfig& config, std::string& exitNode);
    void CommitPending(const std::string& exitNode);

    [[nodiscard]] ExitNodeAction Handle(const tailgate::net::packet::Ipv4UdpDatagram& datagram,
                                        const app_service::ExitNodeRequest& request,
                                        const tailgate::types::netmap::NetworkConfig& config,
                                        const std::string& currentExitNode,
                                        std::vector<std::vector<std::uint8_t>>& appResponses);

    void QueuePendingResponse(std::vector<std::vector<std::uint8_t>>& appResponses);

private:
    struct PendingChange
    {
        std::uint64_t Sequence = 0;
        std::uint32_t AppAddress = 0;
        std::uint16_t AppPort = 0;
        std::string RequestedExitNode;
        std::string ActiveExitNode;
        bool PreserveSelection = false;
        app_service::Status Result = app_service::Status::Ok;
    };

    static void Store(const PendingChange& pending);
    [[nodiscard]] std::optional<PendingChange> Load();
    static void Remove();

    std::optional<PendingChange> m_pending;
    std::vector<std::vector<std::uint8_t>> m_responses;
    bool m_responseReady = false;
    tailgate::base::Logger m_logger{"uwp-exit-node"};
};

} // namespace tailgate::uwp::bg::service
