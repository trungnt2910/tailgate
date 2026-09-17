#include "LocalServicesImpl.h"

#include <algorithm>
#include <set>
#include <string_view>

#include <tailgate/net/packet/Ip.h>

namespace tailgate::ipn::ipnlocal::impl
{

namespace
{

constexpr std::uint16_t DrivePort = 8080;
constexpr std::size_t MaximumPollCycles = 16;
constexpr std::size_t MaximumAcceptsPerCycle = 32;

} // namespace

LocalServicesImpl::LocalServicesImpl(std::shared_ptr<wgengine::netstack::Stack> stack,
                                     std::shared_ptr<drive::FileSystemForLocal> drive,
                                     std::shared_ptr<base::TimeProvider> timeProvider)
    : m_ownedStack(std::move(stack)),
      m_ownedDrive(std::move(drive)),
      m_ownedTimeProvider(std::move(timeProvider)),
      m_stack(*m_ownedStack),
      m_drive(*m_ownedDrive),
      m_timeProvider(*m_ownedTimeProvider)
{
}

LocalServicesImpl::~LocalServicesImpl()
{
    Stop();
}

void LocalServicesImpl::SetNetworkConfig(const types::netmap::NetworkConfig& config)
{
    wgengine::netstack::Configuration next;
    next.Service.Ipv4 = net::IpAddress::Parse("100.100.100.100");
    next.Service.Ipv6 = net::IpAddress::Parse("fd7a:115c:a1e0::53");
    for (const auto& text : config.SelfAddresses().empty()
                                ? std::vector<std::string>{config.SelfAddress()}
                                : config.SelfAddresses())
    {
        const auto address = net::IpAddress::TryParse(text);
        if (!address || address->IsUnspecified())
        {
            continue;
        }
        if (address->Family() == net::AddressFamily::Ipv4 && next.Node.Ipv4.IsUnspecified())
        {
            next.Node.Ipv4 = *address;
        }
        else if (address->Family() == net::AddressFamily::Ipv6 && !next.Node.Ipv6)
        {
            next.Node.Ipv6 = address;
        }
    }
    if (config.SelfKey().empty() || next.Node.Ipv4.IsUnspecified())
    {
        Stop();
        return;
    }
    if (m_started &&
        (m_selfKey != config.SelfKey() || next.Node.Ipv4 != m_configuration.Node.Ipv4 ||
         next.Node.Ipv6 != m_configuration.Node.Ipv6))
    {
        Stop();
    }
    m_drive.SetNetworkConfig(config);
    UpdatePeers(config);
    if (!m_started)
    {
        m_configuration = next;
        m_selfKey = config.SelfKey();
        m_stack.Start(next);
        try
        {
            m_stack.Listen({.Address = next.Service.Ipv4, .Port = DrivePort});
            if (next.Node.Ipv6)
            {
                m_stack.Listen({.Address = *next.Service.Ipv6, .Port = DrivePort});
            }
            m_started = true;
        }
        catch (...)
        {
            m_stack.Stop();
            throw;
        }
    }
    m_moreWork = true;
}

void LocalServicesImpl::Stop() noexcept
{
    if (m_started)
    {
        m_drive.Stop();
        m_stack.Stop();
    }
    m_peersByAddress.clear();
    m_selfKey.clear();
    m_started = false;
    m_moreWork = false;
}

void LocalServicesImpl::Poll()
{
    if (!m_started)
    {
        return;
    }
    m_stack.Poll();
    for (std::size_t cycle = 0; cycle < MaximumPollCycles; ++cycle)
    {
        bool accepted = false;
        for (std::size_t count = 0; count < MaximumAcceptsPerCycle; ++count)
        {
            auto stream = m_stack.TakeAccepted();
            if (!stream)
            {
                break;
            }
            m_drive.HandleConn(std::move(stream));
            accepted = true;
        }
        m_moreWork = m_drive.Poll() || accepted;
        if (!m_moreWork)
        {
            break;
        }
    }
}

std::optional<base::TimeProvider::TimePoint> LocalServicesImpl::NextDeadline() const
{
    if (!m_started)
    {
        return std::nullopt;
    }
    if (m_moreWork || m_stack.HasOutput(wgengine::netstack::PacketPath::Host) ||
        m_stack.HasOutput(wgengine::netstack::PacketPath::HostNetwork) ||
        m_stack.HasOutput(wgengine::netstack::PacketPath::Peer))
    {
        return m_timeProvider.Now();
    }
    const auto tcp = m_stack.NextDeadline();
    const auto drive = m_drive.NextDeadline();
    return tcp && drive ? std::min(*tcp, *drive) : tcp ? tcp : drive;
}

namespace
{

constexpr std::uint8_t TcpProtocol = 6;

bool NeedsTcpDemultiplexing(const net::packet::IpEnvelope& envelope)
{
    if (envelope.Protocol == TcpProtocol)
    {
        return true;
    }
    // An extension after an IPv6 fragment header may conceal TCP. Intercept
    // every fragment consistently, including non-TCP first fragments, then let
    // upstream reassembly and the raw callback return unowned datagrams.
    constexpr std::uint8_t HopByHop = 0;
    constexpr std::uint8_t Routing = 43;
    constexpr std::uint8_t DestinationOptions = 60;
    return envelope.Fragmented &&
           (envelope.FragmentProtocol == HopByHop || envelope.FragmentProtocol == Routing ||
            envelope.FragmentProtocol == DestinationOptions);
}

std::optional<crypto::Bytes32> NodeKey(std::string_view text)
{
    if (text.starts_with("nodekey:"))
    {
        text.remove_prefix(std::string_view("nodekey:").size());
    }
    if (text.size() != crypto::Bytes32{}.size() * 2 ||
        !std::ranges::all_of(text,
                             [](char value)
                             {
                                 return (value >= '0' && value <= '9') ||
                                        (value >= 'a' && value <= 'f') ||
                                        (value >= 'A' && value <= 'F');
                             }))
    {
        return std::nullopt;
    }
    const auto decoded = crypto::HexToBytes(std::string(text));
    crypto::Bytes32 result{};
    std::ranges::copy(decoded, result.begin());
    return result;
}

} // namespace

void LocalServicesImpl::UpdatePeers(const types::netmap::NetworkConfig& config)
{
    std::map<std::string, crypto::Bytes32> next;
    std::set<std::string> ambiguous;
    for (const auto& peer : config.Peers())
    {
        const auto key = NodeKey(peer.Key());
        if (!key)
        {
            continue;
        }
        for (const auto& text :
             peer.Addresses().empty() ? std::vector<std::string>{peer.Address()} : peer.Addresses())
        {
            const auto address = net::IpAddress::TryParse(text);
            if (!address || address->IsUnspecified())
            {
                continue;
            }
            const auto name = address->ToString();
            const auto [entry, inserted] = next.emplace(name, *key);
            if (!inserted && entry->second != *key)
            {
                ambiguous.insert(name);
            }
        }
    }
    for (const auto& address : ambiguous)
    {
        next.erase(address);
    }
    const bool retired =
        std::ranges::any_of(m_peersByAddress,
                            [&next](const auto& previous)
                            {
                                const auto current = next.find(previous.first);
                                return current == next.end() || current->second != previous.second;
                            });
    if (m_started && retired)
    {
        m_stack.InvalidatePeerPackets();
    }
    m_peersByAddress = std::move(next);
}

bool LocalServicesImpl::IsService(const net::IpAddress& address) const
{
    return address == m_configuration.Service.Ipv4 || address == m_configuration.Service.Ipv6;
}

bool LocalServicesImpl::IsSelf(const net::IpAddress& address) const
{
    return address == m_configuration.Node.Ipv4 || address == m_configuration.Node.Ipv6;
}

bool LocalServicesImpl::HandleHostPacket(std::span<const std::uint8_t> packet)
{
    const auto envelope = net::packet::ParseIpEnvelope(packet);
    if (!m_started || !envelope || !IsService(envelope->Destination) ||
        !NeedsTcpDemultiplexing(*envelope))
    {
        return false;
    }
    if (IsSelf(envelope->Source))
    {
        (void)m_stack.Input(wgengine::netstack::PacketPath::Host, packet);
        m_moreWork = true;
    }
    return true;
}

bool LocalServicesImpl::HandlePeerPacket(const crypto::Bytes32& authenticatedPeer,
                                         std::span<const std::uint8_t> packet)
{
    const auto envelope = net::packet::ParseIpEnvelope(packet);
    if (!m_started || !envelope || !NeedsTcpDemultiplexing(*envelope))
    {
        return false;
    }
    if (IsService(envelope->Destination))
    {
        return true;
    }
    if (!IsSelf(envelope->Destination))
    {
        return false;
    }
    const auto peer = m_peersByAddress.find(envelope->Source.ToString());
    if (peer == m_peersByAddress.end())
    {
        // Exit-node/subnet-router traffic has a non-node source address. It
        // cannot match a Taildrive endpoint and belongs to the ordinary host path.
        return false;
    }
    if (peer->second != authenticatedPeer)
    {
        return true;
    }
    (void)m_stack.Input(wgengine::netstack::PacketPath::Peer, packet);
    m_moreWork = true;
    return true;
}

std::vector<ServicePacket> LocalServicesImpl::TakeOutput(std::size_t maximumPackets)
{
    std::vector<ServicePacket> result;
    if (!m_started)
    {
        return result;
    }
    for (auto& packet : m_stack.TakeOutput(maximumPackets))
    {
        ServicePacket output;
        output.ForwardFromHost = packet.Path == wgengine::netstack::PacketPath::HostNetwork;
        if (packet.Path == wgengine::netstack::PacketPath::Peer)
        {
            const auto envelope = net::packet::ParseIpEnvelope(packet.Bytes);
            if (!envelope)
            {
                continue;
            }
            const auto peer = m_peersByAddress.find(envelope->Destination.ToString());
            if (peer == m_peersByAddress.end())
            {
                continue;
            }
            output.Peer = peer->second;
        }
        output.Bytes = std::move(packet.Bytes);
        result.push_back(std::move(output));
    }
    return result;
}

} // namespace tailgate::ipn::ipnlocal::impl
