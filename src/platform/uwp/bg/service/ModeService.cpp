#include "ModeService.h"

#include <utility>

#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Ipv4.h>

#include "common/VpnConstants.h"

namespace tailgate::uwp::bg::service
{

ModeService::ModeService(manager::DataPlaneManager& manager)
{
    manager.Register(*this);
}

void ModeService::Start(SessionGeneration)
{
    Reset();
}

void ModeService::Reset()
{
    m_subscriber.reset();
    m_state.Request.reset();
    m_output.clear();
    m_dirty = false;
}

void ModeService::Stop()
{
    Reset();
}

bool ModeService::HasLocalOutput() const
{
    return !m_output.empty();
}

void ModeService::Respond(std::uint32_t address,
                          std::uint16_t port,
                          const app_service::ModeResponse& response)
{
    // A host input batch is bounded, and FlushLocal runs after each batch.
    m_output.push_back(
        tailgate::net::packet::Ipv4UdpDatagram::Build(VpnConstants::Network::ServiceIpv4Address,
                                                      address,
                                                      VpnConstants::AppService::Port,
                                                      port,
                                                      app_service::EncodeModeResponse(response)));
}

void ModeService::Encapsulate(EncapsulationContext& context)
{
    const auto packet = tailgate::net::packet::Ipv4UdpDatagram::Parse(context.Original);
    if (!packet || packet->Destination() != VpnConstants::Network::ServiceIpv4Address ||
        packet->DestinationPort() != VpnConstants::AppService::Port)
    {
        return;
    }
    const auto message = app_service::DecodeMessage(packet->Payload());
    if (!message || message->Type != app_service::MessageType::ModeRequest)
    {
        return;
    }
    context.Handled = true;
    const auto self = tailgate::net::Ipv4Address::TryParse(context.Node.Network().SelfAddress());
    const auto request = app_service::DecodeModeRequest(*message);
    if (!self || packet->Source() != self->HostOrder() || packet->SourcePort() == 0 || !request)
    {
        return;
    }
    if (m_subscriber)
    {
        Respond(packet->Source(),
                packet->SourcePort(),
                {.Result = app_service::Status::Busy,
                 .Sequence = request->Sequence,
                 .Transition = m_status});
        return;
    }
    m_subscriber = Subscriber{
        .Address = packet->Source(), .Port = packet->SourcePort(), .Sequence = request->Sequence};
    m_state.Request = *request;
    m_dirty = true;
}

const ModeServiceState& ModeService::GetState() const noexcept
{
    return m_state;
}

void ModeService::AcknowledgeRequest()
{
    m_state.Request.reset();
}

void ModeService::Publish(const tailgate::ipn::ipnlocal::TransitionStatus& status,
                          app_service::Status result)
{
    const bool changed = m_dirty || status != m_status || result != app_service::Status::Ok;
    m_status = status;
    m_dirty = false;
    if (!changed || !m_subscriber)
    {
        return;
    }
    Respond(m_subscriber->Address,
            m_subscriber->Port,
            {.Result = result, .Sequence = m_subscriber->Sequence, .Transition = status});
    using tailgate::ipn::ipnlocal::TransitionPhase;
    if (status.Phase == TransitionPhase::Idle || status.Phase == TransitionPhase::Failed ||
        result != app_service::Status::Ok)
    {
        m_subscriber.reset();
    }
}

void ModeService::FlushLocal(std::vector<std::vector<std::uint8_t>>& output)
{
    for (auto& packet : m_output)
    {
        output.push_back(std::move(packet));
    }
    m_output.clear();
}

} // namespace tailgate::uwp::bg::service
