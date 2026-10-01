#pragma once

#include "common/UwpAppServiceProtocol.h"
#include "manager/DataPlaneManager.h"
#include "service/ServiceBase.h"

namespace tailgate::uwp::bg::service
{

struct ModeServiceState
{
    std::optional<app_service::ModeRequest> Request;
};

class ModeService final : public ServiceBase
{
public:
    explicit ModeService(manager::DataPlaneManager& manager);
    void Start(SessionGeneration generation) override;
    void Reset() override;
    void Stop() override;
    void Encapsulate(EncapsulationContext& context) override;
    void FlushLocal(std::vector<std::vector<std::uint8_t>>& output) override;
    [[nodiscard]] bool HasLocalOutput() const override;
    [[nodiscard]] const ModeServiceState& GetState() const noexcept;
    void AcknowledgeRequest();
    void Publish(const tailgate::ipn::ipnlocal::TransitionStatus& status,
                 app_service::Status result = app_service::Status::Ok);

private:
    void
    Respond(std::uint32_t address, std::uint16_t port, const app_service::ModeResponse& response);

    struct Subscriber
    {
        std::uint32_t Address = 0;
        std::uint16_t Port = 0;
        std::uint64_t Sequence = 0;
    };

    std::optional<Subscriber> m_subscriber;
    ModeServiceState m_state;
    tailgate::ipn::ipnlocal::TransitionStatus m_status;
    std::vector<std::vector<std::uint8_t>> m_output;
    bool m_dirty = false;
};

} // namespace tailgate::uwp::bg::service
