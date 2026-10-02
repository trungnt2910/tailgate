#include "ChannelAdapter.h"

#include <algorithm>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Networking.h>
#include <winrt/Windows.Storage.Streams.h>

#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Ipv4.h>

#include "common/VpnConstants.h"
#include "common/VpnPhonebook.h"

#include "VpnPacketBufferReader.h"

namespace tailgate::uwp::bg
{
namespace
{
namespace vpn = winrt::Windows::Networking::Vpn;
namespace networking = winrt::Windows::Networking;
namespace streams = winrt::Windows::Storage::Streams;
using manager::ChannelPolicy;

vpn::VpnDomainNameAssignment BuildDomainAssignment(const ChannelPolicy& policy)
{
    vpn::VpnDomainNameAssignment assignment;
    for (const auto& entry : policy.DnsNamespaces)
    {
        auto dnsServers = winrt::single_threaded_vector<networking::HostName>();
        for (const auto& resolver : entry.Resolvers)
        {
            dnsServers.Append(networking::HostName(winrt::to_hstring(resolver)));
        }
        assignment.DomainNameList().Append(vpn::VpnDomainNameInfo(
            winrt::to_hstring(entry.Suffix), vpn::VpnDomainNameType::Suffix, dnsServers, nullptr));
    }
    return assignment;
}

void FillPacket(const vpn::VpnPacketBuffer& packet, const std::vector<std::uint8_t>& bytes)
{
    const streams::Buffer buffer = packet.Buffer();
    if (bytes.size() > buffer.Capacity())
    {
        throw std::runtime_error("UWP VPN packet exceeds packet buffer capacity.");
    }
    std::copy(bytes.begin(), bytes.end(), buffer.data());
    buffer.Length(static_cast<std::uint32_t>(bytes.size()));
}

bool AppendPacket(const vpn::VpnChannel& channel,
                  const vpn::VpnPacketBufferList& packets,
                  vpn::VpnDataPathType type,
                  const std::vector<std::uint8_t>& bytes)
{
    vpn::VpnPacketBuffer packet{nullptr};
    channel.RequestVpnPacketBuffer(type, packet);
    // Transfer ownership before filling, so an exception cannot leak a buffer.
    packet.Buffer().Length(0);
    packets.Append(packet);
    if (bytes.size() > packet.Buffer().Capacity())
    {
        return false;
    }
    FillPacket(packet, bytes);
    return true;
}

vpn::VpnRouteAssignment BuildRouteAssignment(const manager::ChannelPolicy& policy)
{
    auto routes = winrt::single_threaded_vector<vpn::VpnRoute>();
    for (const tailgate::net::packet::Ipv4Prefix& prefix : policy.Routes)
    {
        const std::string address =
            tailgate::net::Ipv4Address::FromHostOrder(prefix.Network()).ToString();
        routes.Append(
            vpn::VpnRoute(networking::HostName(winrt::to_hstring(address)), prefix.PrefixLength()));
    }

    auto excluded = winrt::single_threaded_vector<vpn::VpnRoute>();
    for (const auto& prefix : policy.ExcludedRoutes)
    {
        excluded.Append(vpn::VpnRoute(
            networking::HostName(winrt::to_hstring(
                tailgate::net::Ipv4Address::FromHostOrder(prefix.Network()).ToString())),
            prefix.PrefixLength()));
    }
    vpn::VpnRouteAssignment assignment;
    assignment.Ipv4InclusionRoutes(routes);
    assignment.Ipv4ExclusionRoutes(excluded);
    assignment.ExcludeLocalSubnets(true);
    return assignment;
}

} // namespace

ChannelAdapter::ChannelAdapter(std::shared_ptr<tailgate::base::EventLoop> events,
                               tailgate::base::TimeProvider& time)
    : m_events(std::move(events)), m_loopback(m_events, time)
{
}

void ChannelAdapter::Open(const vpn::VpnChannel& channel,
                          const std::string& derpHost,
                          std::stop_token cancellation)
{
    std::string_view stage = "DerpWakeTransport.Prepare";
    try
    {
        m_derpWake.Prepare();
        stage = "LoopbackTransport.Open";
        m_loopback.Open(channel, m_derpWake.Socket(), cancellation);
        stage = "DerpWakeTransport.Connect";
        m_derpWake.Connect(derpHost, cancellation);
    }
    catch (...)
    {
        m_logger.LogError("transport setup failed stage={} hresult=0x{:08x} cancelled={}: {}",
                          stage,
                          static_cast<std::uint32_t>(winrt::to_hresult().value),
                          cancellation.stop_requested(),
                          winrt::to_message());
        throw;
    }
}

void ChannelAdapter::Start(const vpn::VpnChannel& channel, const manager::ChannelPolicy& policy)
{
    auto assignedIpv4 = winrt::single_threaded_vector<networking::HostName>();
    assignedIpv4.Append(networking::HostName(winrt::to_hstring(policy.Ipv4Address)));
    auto assignedIpv6 = winrt::single_threaded_vector<networking::HostName>();
    for (const auto& address : policy.Ipv6Addresses)
    {
        assignedIpv6.Append(networking::HostName(winrt::to_hstring(address)));
    }
    const auto ipv6 = assignedIpv6.Size() == 0 ? nullptr : assignedIpv6.GetView();
    const auto routes = BuildRouteAssignment(policy);
    const auto domains = BuildDomainAssignment(policy);
    const auto transport = m_loopback.Socket();
    m_logger.LogInfo("starting channel inclusion-routes={} exclusion-routes={}",
                     policy.Routes.size(),
                     policy.ExcludedRoutes.size());
    {
        std::lock_guard lock(m_mutex);
        m_enabled = true;
    }
    try
    {
        channel.StartWithTrafficFilter(assignedIpv4.GetView(),
                                       ipv6,
                                       nullptr,
                                       routes,
                                       domains,
                                       VpnConstants::Channel::Mtu,
                                       VpnConstants::Channel::MaximumFrameSize,
                                       false,
                                       m_derpWake.Socket(),
                                       transport,
                                       nullptr);
    }
    catch (...)
    {
        m_logger.LogError("setup failed api=VpnChannel.StartWithTrafficFilter hresult=0x{:08x}: {}",
                          static_cast<std::uint32_t>(winrt::to_hresult().value),
                          winrt::to_message());
        throw;
    }
    {
        std::lock_guard lock(m_mutex);
        m_started = true;
    }
    m_loopback.StartPulsing();
    m_derpWake.Start();
    // Older Windows can rewrite DEVICE=modem during Start, misclassifying the VPN in
    // Settings. Repair once on this callback worker, including Settings-initiated connections.
    VpnPhonebook::RepairAsync(winrt::Windows::Storage::ApplicationData::Current().LocalFolder())
        .get();
}

void ChannelAdapter::Close()
{
    m_derpWake.Close();
    std::lock_guard lock(m_mutex);
    m_enabled = m_started = false;
    m_loopback.Close();
    m_input.clear();
    m_output.clear();
    m_inputBytes = m_outputBytes = 0;
}

bool ChannelAdapter::Failed() const noexcept
{
    return m_loopback.Failed();
}

void ChannelAdapter::KeepAlive(const vpn::VpnChannel& channel, vpn::VpnPacketBuffer& packet)
{
    std::lock_guard lock(m_mutex);
    packet = nullptr;
    if (m_started)
    {
        channel.RequestVpnPacketBuffer(vpn::VpnDataPathType::Send, packet);
        packet.TransportAffinity(VpnConstants::Channel::LoopbackTransportAffinity);
        FillPacket(packet, {0});
    }
}

void ChannelAdapter::Encapsulate(const vpn::VpnPacketBufferList& packets,
                                 const vpn::VpnPacketBufferList& output)
{
    std::lock_guard lock(m_mutex);
    if (!m_enabled)
    {
        return;
    }
    const auto count = packets.Size();
    for (std::uint32_t index = 0; index < count; ++index)
    {
        auto bytes = VpnPacketBufferReader::Read(
            packets, output, VpnConstants::Channel::LoopbackTransportAffinity);
        if (m_input.size() >= MaximumPackets || m_inputBytes + bytes.size() > MaximumBytes)
        {
            m_logger.LogWarning("host packet queue is full; dropping packet");
            continue;
        }
        m_inputBytes += bytes.size();
        m_input.push_back(std::move(bytes));
    }
    m_events->Wake();
}

void ChannelAdapter::Decapsulate(const vpn::VpnChannel& channel,
                                 const vpn::VpnPacketBuffer& input,
                                 const vpn::VpnPacketBufferList& packets)
{
    if (input)
    {
        const auto buffer = input.Buffer();
        const auto affinity = input.TransportAffinity();
        if (affinity == VpnConstants::Channel::DerpTransportAffinity)
        {
            m_derpWake.Receive({buffer.data(), buffer.Length()});
        }
    }
    std::lock_guard lock(m_mutex);
    if (!m_enabled)
    {
        return;
    }
    bool blocked = false;
    bool delivered = false;
    try
    {
        for (std::size_t count = 0; count < MaximumPacketsPerTurn && !m_output.empty(); ++count)
        {
            // Keep the queued packet until Windows has accepted its buffer.
            if (!AppendPacket(channel, packets, vpn::VpnDataPathType::Receive, m_output.front()))
            {
                m_logger.LogWarning("dropping packet larger than the VPN receive buffer: {}",
                                    m_output.front().size());
            }
            m_outputBytes -= m_output.front().size();
            m_output.pop_front();
            delivered = true;
        }
    }
    catch (...)
    {
        blocked = true;
        m_logger.LogWarning("VPN packet delivery deferred: {}", winrt::to_message());
    }
    if (!blocked && !m_output.empty())
    {
        m_loopback.Wake();
    }
    if (delivered)
    {
        m_events->Wake();
    }
}

void ChannelAdapter::QueueOutput(std::vector<std::vector<std::uint8_t>> packets)
{
    std::lock_guard lock(m_mutex);
    for (auto& packet : packets)
    {
        if (m_output.size() >= MaximumPackets || m_outputBytes + packet.size() > MaximumBytes)
        {
            m_logger.LogWarning("VPN output queue is full; dropping packet");
            continue;
        }
        m_outputBytes += packet.size();
        m_output.push_back(std::move(packet));
    }
    if (!m_output.empty())
    {
        m_loopback.Wake();
    }
}

std::vector<std::vector<std::uint8_t>> ChannelAdapter::TakeInput(std::size_t maximumPackets)
{
    std::lock_guard lock(m_mutex);
    std::vector<std::vector<std::uint8_t>> result;
    while (result.size() < maximumPackets && !m_input.empty())
    {
        m_inputBytes -= m_input.front().size();
        result.push_back(std::move(m_input.front()));
        m_input.pop_front();
    }
    if (!m_input.empty())
    {
        m_events->Wake();
    }
    return result;
}

} // namespace tailgate::uwp::bg
