#include "PingService.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include <boost/algorithm/string/case_conv.hpp>

#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Ipv4.h>

#include "common/VpnConstants.h"

namespace tailgate::uwp::bg::service
{
namespace
{

constexpr std::chrono::seconds PingExpiry(10);

std::vector<std::uint8_t> BuildResponse(std::uint32_t appAddress,
                                        std::uint16_t appPort,
                                        app_service::Status status,
                                        std::uint64_t sequence,
                                        std::uint32_t latencyMicroseconds = 0,
                                        const std::string& relayName = {},
                                        const std::string& endpoint = {},
                                        bool direct = false)
{
    const std::vector<std::uint8_t> payload =
        app_service::EncodePingResponse(app_service::PingResponse{
            .Result = status,
            .Sequence = sequence,
            .LatencyMicroseconds = latencyMicroseconds,
            .Direct = direct,
            .Relay = relayName,
            .Endpoint = endpoint,
        });
    return tailgate::net::packet::Ipv4UdpDatagram::Build(VpnConstants::Network::ServiceIpv4Address,
                                                         appAddress,
                                                         VpnConstants::AppService::Port,
                                                         appPort,
                                                         payload);
}

} // namespace

PingService::PingService(manager::DataPlaneManager& dataPlaneManager,
                         tailgate::base::TimeProvider& time)
    : m_time(time)
{
    dataPlaneManager.Register(*this);
}

void PingService::Start(SessionGeneration)
{
}

void PingService::Stop()
{
    Reset();
}

void PingService::Reset()
{
    m_pending.clear();
    m_responses.clear();
    m_nextRequestId = 1;
}

void PingService::Encapsulate(EncapsulationContext& context)
{
    const auto datagram = tailgate::net::packet::Ipv4UdpDatagram::Parse(context.Original);
    if (!datagram || datagram->Destination() != VpnConstants::Network::ServiceIpv4Address ||
        datagram->DestinationPort() != VpnConstants::AppService::Port)
    {
        return;
    }
    const auto message = app_service::DecodeMessage(datagram->Payload());
    if (!message || message->Type != app_service::MessageType::PingRequest)
    {
        return;
    }
    context.Handled = true;
    const auto self = tailgate::net::Ipv4Address::TryParse(context.Node.Network().SelfAddress());
    const auto request = app_service::DecodePingRequest(*message);
    if (!self || datagram->Source() != self->HostOrder() || datagram->SourcePort() == 0 || !request)
    {
        m_logger.LogWarning("discarding invalid in-tunnel ping request");
        return;
    }
    std::string selectedRelay = context.RelayName;
    boost::algorithm::to_lower(selectedRelay);
    const auto requestId = m_nextRequestId++;
    const auto status = context.Node.StartPing({.Id = requestId,
                                                .Target = request->Target,
                                                .PingMode = tailgate::wgengine::ping::Mode::Disco,
                                                .Timeout = PingExpiry,
                                                .Relay = std::move(selectedRelay)});
    if (status != tailgate::wgengine::ping::StartStatus::Ready)
    {
        m_responses.push_back(
            BuildResponse(datagram->Source(),
                          datagram->SourcePort(),
                          status == tailgate::wgengine::ping::StartStatus::NoMatchingPeer
                              ? app_service::Status::NoMatchingPeer
                              : app_service::Status::NoDiscoKey,
                          request->Sequence));
        return;
    }
    m_pending.push_back(PendingResponse{.RequestId = requestId,
                                        .Sequence = request->Sequence,
                                        .AppAddress = datagram->Source(),
                                        .AppPort = datagram->SourcePort(),
                                        .Hosted = !context.RelayName.empty(),
                                        .Deadline = m_time.Now() + PingExpiry});
    m_logger.LogDebug("app ping sent seq={} target={}", request->Sequence, request->Target);
}

void PingService::FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput)
{
    for (std::vector<std::uint8_t>& response : m_responses)
    {
        localOutput.push_back(std::move(response));
    }
    m_responses.clear();
}

bool PingService::HasLocalOutput() const
{
    return !m_responses.empty();
}

std::optional<tailgate::base::TimeProvider::TimePoint> PingService::NextDeadline() const
{
    const auto next = std::ranges::min_element(m_pending, {}, &PendingResponse::Deadline);
    return next == m_pending.end() ? std::nullopt : std::optional(next->Deadline);
}

void PingService::Complete(const tailgate::wgengine::ping::Result& result,
                           bool direct,
                           const std::string& endpoint)
{
    const auto pending = std::ranges::find_if(m_pending,
                                              [&](const PendingResponse& candidate)
                                              {
                                                  return candidate.RequestId == result.RequestId;
                                              });
    if (pending == m_pending.end())
    {
        return;
    }
    const auto latency = std::clamp<std::int64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(result.Latency).count(),
        0,
        std::numeric_limits<std::uint32_t>::max());
    std::string relay = result.Relay;
    if (!pending->Hosted)
    {
        boost::algorithm::to_upper(relay);
    }
    m_responses.push_back(
        BuildResponse(pending->AppAddress,
                      pending->AppPort,
                      result.Responded ? app_service::Status::Ok : app_service::Status::Timeout,
                      pending->Sequence,
                      static_cast<std::uint32_t>(latency),
                      direct ? std::string{} : relay,
                      endpoint,
                      direct));
    m_logger.LogDebug("app ping completed seq={} responded={} latency-us={} direct={}",
                      pending->Sequence,
                      result.Responded,
                      latency,
                      direct);
    m_pending.erase(pending);
}

} // namespace tailgate::uwp::bg::service
