#include "NetworkService.h"

#include <optional>
#include <utility>

#include <tailgate/hosted/Client.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>

#include "common/VpnConstants.h"

#include "PingService.h"

namespace tailgate::uwp::bg::service
{

const char* NetworkServiceError::what() const noexcept
{
    switch (m_code)
    {
    case NetworkServiceErrorCode::PacketDeviceAlreadyOpen:
        return "packet device is already open";
    case NetworkServiceErrorCode::PacketQueueFull:
        return "packet device queue is full";
    case NetworkServiceErrorCode::PacketDeviceClosed:
        return "packet device is closed";
    }
    return "unknown network service error";
}

NetworkService::NetworkService(manager::DataPlaneManager& dataPlaneManager,
                               manager::SessionManager& sessionManager,
                               PingService& pingService,
                               tailgate::hosted::Client& client,
                               tailgate::hosted::ClientSession& hostedSession,
                               PacketDevice& packetDevice)
    : m_client(client),
      m_hostedSession(hostedSession),
      m_packetDevice(packetDevice),
      m_pingService(pingService),
      m_sessionManager(sessionManager)
{
    dataPlaneManager.Register(*this);
}

void NetworkService::Start(SessionGeneration)
{
    static constexpr tailgate::base::EventToken PacketDeviceToken{.Value = 1};
    if (!m_hostedSession.OpenPacketDevice(tailgate::wgengine::tstun::DeviceOptions{
            .Name = {},
            .ReadinessToken = PacketDeviceToken,
        }))
    {
        throw NetworkServiceError(NetworkServiceErrorCode::PacketDeviceAlreadyOpen);
    }
}

void NetworkService::Stop()
{
    m_hostedSession.ClosePacketDevice();
    m_client.Stop();
}

void NetworkService::Reset()
{
    m_hostedSession.ClosePacketDevice();
    m_client.Stop();
}

void NetworkService::Encapsulate(EncapsulationContext& context)
{
    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> datagram =
        tailgate::net::packet::Ipv4UdpDatagram::Parse(context.Original);
    if (datagram && ((datagram->Destination() == VpnConstants::Network::ServiceIpv4Address &&
                      datagram->DestinationPort() == VpnConstants::AppService::Port) ||
                     (datagram->Destination() == tailgate::net::dns::MagicDnsIpv4Address &&
                      datagram->DestinationPort() == tailgate::net::dns::DnsPort)))
    {
        return;
    }
    if (m_packetDevice.QueueInput(context.Original) != PacketQueueResult::Complete)
    {
        throw NetworkServiceError(NetworkServiceErrorCode::PacketQueueFull);
    }
    tailgate::hosted::ClientSessionProcessResult result =
        m_hostedSession.ProcessPacketDevice(1, context.Original.size());
    if (result.DeviceStatus != tailgate::hosted::PacketDeviceStatus::Ready)
    {
        throw NetworkServiceError(NetworkServiceErrorCode::PacketDeviceClosed);
    }
    context.RemoteOutput.insert(
        context.RemoteOutput.end(), result.RemoteOutput.begin(), result.RemoteOutput.end());
}

void NetworkService::Decapsulate(DecapsulationContext& context)
{
    tailgate::hosted::ClientSessionProcessResult result =
        m_hostedSession.ProcessFrame(context.Message);
    if (result.NetworkMapChanged)
    {
        m_sessionManager.WriteState(context.Client.Network());
    }
    if (result.Pong)
    {
        m_pingService.Complete(result.Pong->Message, result.Pong->Packet);
    }
    context.RemoteOutput.insert(
        context.RemoteOutput.end(), result.RemoteOutput.begin(), result.RemoteOutput.end());
    if (result.DeviceStatus != tailgate::hosted::PacketDeviceStatus::Ready)
    {
        throw NetworkServiceError(NetworkServiceErrorCode::PacketDeviceClosed);
    }
    DrainDevice(context.LocalOutput);
}

void NetworkService::FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput)
{
    if (m_hostedSession.FlushPacketDevice() == tailgate::hosted::PacketDeviceStatus::Closed)
    {
        throw NetworkServiceError(NetworkServiceErrorCode::PacketDeviceClosed);
    }
    DrainDevice(localOutput);
}

void NetworkService::DrainDevice(std::vector<std::vector<std::uint8_t>>& localOutput)
{
    std::vector<std::vector<std::uint8_t>> packets = m_packetDevice.DrainOutput();
    localOutput.insert(localOutput.end(),
                       std::make_move_iterator(packets.begin()),
                       std::make_move_iterator(packets.end()));
}

} // namespace tailgate::uwp::bg::service
