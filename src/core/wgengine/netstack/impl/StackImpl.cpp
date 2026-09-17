#include "StackImpl.h"

#include <algorithm>
#include <limits>
#include <mutex>
#include <new>
#include <utility>

#include <lwip/ip.h>
#include <lwip/prot/ip6.h>
#include <lwip/prot/tcp.h>

#include <tailgate/wgengine/netstack/Error.h>

#include "IpAddress.h"
#include "StreamImpl.h"

namespace tailgate::wgengine::netstack::impl
{

namespace
{

constexpr std::uint16_t InterfaceMtu = 1280;

bool ValidAddresses(const InterfaceAddresses& addresses)
{
    return addresses.Ipv4.Family() == net::AddressFamily::Ipv4 && !addresses.Ipv4.IsUnspecified() &&
           (!addresses.Ipv6 || (addresses.Ipv6->Family() == net::AddressFamily::Ipv6 &&
                                !addresses.Ipv6->IsUnspecified()));
}

} // namespace

StackImpl::StackImpl(std::shared_ptr<Runtime> runtime,
                     types::nettype::TcpPortReservationFactory& portReservations)
    : m_runtime(std::move(runtime)), m_portReservations(portReservations)
{
    m_service.Owner = this;
    m_service.Path = PacketPath::Host;
    m_node.Owner = this;
    m_node.Path = PacketPath::Peer;
}

StackImpl::~StackImpl()
{
    Stop();
}

void StackImpl::Start(const Configuration& configuration)
{
    std::lock_guard lock(m_runtime->Mutex());
    if (m_started || m_runtime->Started())
    {
        throw Exception(Error::RuntimeInUse);
    }
    if (!ValidAddresses(configuration.Service) || !ValidAddresses(configuration.Node) ||
        configuration.Service.Ipv4 == configuration.Node.Ipv4 ||
        (configuration.Service.Ipv6 && configuration.Service.Ipv6 == configuration.Node.Ipv6))
    {
        throw Exception(Error::InvalidAddress);
    }
    m_runtime->Start();
    try
    {
        m_configuration = configuration;
        AddInterface(m_service, configuration.Service);
        AddInterface(m_node, configuration.Node);
        AddDemultiplexer();
        netif_set_default(&m_node.Native);
        m_started = true;
    }
    catch (...)
    {
        RemoveDemultiplexer();
        if (m_node.Added)
        {
            netif_remove(&m_node.Native);
            m_node.Added = false;
        }
        if (m_service.Added)
        {
            netif_remove(&m_service.Native);
            m_service.Added = false;
        }
        m_runtime->Stop();
        throw;
    }
}

void StackImpl::Stop() noexcept
{
    std::deque<std::unique_ptr<Stream>> retired;
    {
        std::lock_guard lock(m_runtime->Mutex());
        if (!m_started)
        {
            return;
        }
        m_runtime->ClearConnections();
        // Release connection handles outside the runtime lock: their destructors
        // acquire it as well. The PCB destruction callbacks have already invalidated them.
        retired.swap(m_accepted);
        RemoveDemultiplexer();
        netif_remove(&m_node.Native);
        netif_remove(&m_service.Native);
        m_runtime->Stop();
        m_node.Added = false;
        m_service.Added = false;
        m_output.clear();
        m_outputBytes = 0;
        m_started = false;
    }
}

void StackImpl::RequireStarted() const
{
    if (!m_started)
    {
        throw Exception(Error::NotStarted);
    }
}

void StackImpl::AddInterface(Interface& interface, const InterfaceAddresses& addresses)
{
    const auto address = NativeAddress(addresses.Ipv4);
    const auto mask =
        NativeAddress(net::IpAddress(net::Ipv4Address::FromOctets(255, 255, 255, 255)));
    const ip4_addr_t gateway{};
    interface.Native = {};
    if (netif_add(&interface.Native,
                  ip_2_ip4(&address),
                  ip_2_ip4(&mask),
                  &gateway,
                  &interface,
                  InitializeInterface,
                  ip_input) == nullptr)
    {
        throw Exception(Error::CapacityExceeded);
    }
    interface.Added = true;
    if (addresses.Ipv6)
    {
        const auto ipv6 = NativeAddress(*addresses.Ipv6);
        netif_ip6_addr_set(&interface.Native, 0, ip_2_ip6(&ipv6));
        netif_ip6_addr_set_state(&interface.Native, 0, IP6_ADDR_PREFERRED);
    }
    netif_set_up(&interface.Native);
    netif_set_link_up(&interface.Native);
}

err_t StackImpl::InitializeInterface(netif* interface) noexcept
{
    interface->name[0] = 't';
    interface->name[1] = 'g';
    interface->mtu = InterfaceMtu;
    interface->output = Output4;
    interface->output_ip6 = Output6;
    return ERR_OK;
}

void StackImpl::Poll()
{
    std::lock_guard lock(m_runtime->Mutex());
    RequireStarted();
    m_runtime->Poll();
}

std::optional<base::TimeProvider::TimePoint> StackImpl::NextDeadline() const
{
    std::lock_guard lock(m_runtime->Mutex());
    return m_started ? m_runtime->NextDeadline() : std::nullopt;
}

namespace
{

constexpr std::uint8_t AcceptBacklog = 8;
constexpr std::size_t MaximumAcceptedConnections = MEMP_NUM_TCP_PCB;

} // namespace

void StackImpl::Listen(const TcpEndpoint& endpoint)
{
    std::lock_guard lock(m_runtime->Mutex());
    RequireStarted();
    if (endpoint.Port == 0 || (endpoint.Address != m_configuration.Service.Ipv4 &&
                               endpoint.Address != m_configuration.Service.Ipv6))
    {
        throw Exception(Error::InvalidAddress);
    }
    const auto address = NativeAddress(endpoint.Address);
    auto* pcb = tcp_new_ip_type(IP_GET_TYPE(&address));
    if (pcb == nullptr)
    {
        throw Exception(Error::CapacityExceeded);
    }
    tcp_bind_netif(pcb, &m_service.Native);
    if (tcp_bind(pcb, &address, endpoint.Port) != ERR_OK)
    {
        tcp_abort(pcb);
        throw Exception(Error::ConnectionFailed);
    }
    auto* listener = tcp_listen_with_backlog(pcb, AcceptBacklog);
    if (listener == nullptr)
    {
        tcp_abort(pcb);
        throw Exception(Error::CapacityExceeded);
    }
    if (!m_runtime->Track(listener))
    {
        (void)tcp_close(listener);
        throw Exception(Error::CapacityExceeded);
    }
    tcp_arg(listener, this);
    tcp_accept(listener, Accepted);
}

std::unique_ptr<Stream> StackImpl::Connect(const TcpEndpoint& endpoint)
{
    std::unique_lock lock(m_runtime->Mutex());
    RequireStarted();
    m_runtime->Poll();
    const bool ipv6 = endpoint.Address.Family() == net::AddressFamily::Ipv6;
    if (endpoint.Port == 0 || endpoint.Address.IsUnspecified() ||
        (ipv6 && !m_configuration.Node.Ipv6))
    {
        throw Exception(Error::InvalidAddress);
    }
    const auto remote = NativeAddress(endpoint.Address);
    const auto localAddress = ipv6 ? *m_configuration.Node.Ipv6 : m_configuration.Node.Ipv4;
    const auto local = NativeAddress(localAddress);
    auto reservation = m_portReservations.TryReserve(localAddress);
    if (!reservation || reservation->Port() == 0)
    {
        throw Exception(Error::ConnectionFailed);
    }
    auto* pcb = tcp_new_ip_type(IP_GET_TYPE(&remote));
    if (pcb == nullptr)
    {
        throw Exception(Error::CapacityExceeded);
    }
    tcp_bind_netif(pcb, &m_node.Native);
    if (tcp_bind(pcb, &local, reservation->Port()) != ERR_OK)
    {
        tcp_abort(pcb);
        throw Exception(Error::ConnectionFailed);
    }
    std::unique_ptr<StreamImpl> stream;
    try
    {
        stream = std::make_unique<StreamImpl>(m_runtime, pcb, StreamState::Connecting);
    }
    catch (...)
    {
        tcp_abort(pcb);
        throw;
    }
    if (!m_runtime->ReservePort(pcb, std::move(reservation)) ||
        tcp_connect(pcb, &remote, endpoint.Port, StreamImpl::Connected) != ERR_OK)
    {
        lock.unlock();
        stream->Abort();
        throw Exception(Error::ConnectionFailed);
    }
    return stream;
}

err_t StackImpl::Accepted(void* context, tcp_pcb* pcb, err_t error) noexcept
{
    auto& stack = *static_cast<StackImpl*>(context);
    if (pcb == nullptr)
    {
        return ERR_MEM;
    }
    if (error != ERR_OK || stack.m_accepted.size() >= MaximumAcceptedConnections)
    {
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    try
    {
        // Allocate the queue slot before constructing a stream: destroying a stream
        // inside this raw callback would recursively acquire the runtime lock.
        stack.m_accepted.emplace_back();
        stack.m_accepted.back() =
            std::make_unique<StreamImpl>(stack.m_runtime, pcb, StreamState::Open);
        return ERR_OK;
    }
    catch (const std::bad_alloc&)
    {
        // Preserve the existing accepted queue if its own growth was refused.
    }
    catch (const Exception&)
    {
        // Tracking capacity can refuse a connection without unwinding through C.
    }
    if (!stack.m_accepted.empty() && !stack.m_accepted.back())
    {
        stack.m_accepted.pop_back();
    }
    tcp_abort(pcb);
    return ERR_ABRT;
}

std::unique_ptr<Stream> StackImpl::TakeAccepted()
{
    std::lock_guard lock(m_runtime->Mutex());
    if (m_accepted.empty())
    {
        return nullptr;
    }
    auto result = std::move(m_accepted.front());
    m_accepted.pop_front();
    return result;
}

namespace
{

bool CarriesTcp(pbuf* packet, std::uint16_t headerLength) noexcept
{
    if (!ip_current_is_v6())
    {
        return IPH_PROTO(ip4_current_header()) == IP_PROTO_TCP;
    }
    // raw_input matches the IPv6 base header, not its final next-header value.
    // The upstream IP layer has already validated/reassembled the extension chain.
    auto protocol = IP6H_NEXTH(ip6_current_header());
    std::uint16_t offset = IP6_HLEN;
    while (offset < headerLength)
    {
        if (protocol != IP6_NEXTH_HOPBYHOP && protocol != IP6_NEXTH_ROUTING &&
            protocol != IP6_NEXTH_DESTOPTS && protocol != IP6_NEXTH_FRAGMENT)
        {
            return false;
        }
        const auto length = protocol == IP6_NEXTH_FRAGMENT
                                ? IP6_FRAG_HLEN
                                : (static_cast<unsigned>(pbuf_get_at(packet, offset + 1)) + 1) * 8;
        protocol = pbuf_get_at(packet, offset);
        if (length > static_cast<unsigned>(headerLength - offset))
        {
            return false;
        }
        offset = static_cast<std::uint16_t>(offset + length);
    }
    return protocol == IP6_NEXTH_TCP;
}

} // namespace

void StackImpl::AddDemultiplexer()
{
    constexpr std::array<std::uint8_t, 5> Protocols{IP_PROTO_TCP,
                                                    IP6_NEXTH_HOPBYHOP,
                                                    IP6_NEXTH_ROUTING,
                                                    IP6_NEXTH_FRAGMENT,
                                                    IP6_NEXTH_DESTOPTS};
    static_assert(Protocols.size() == MEMP_NUM_RAW_PCB);
    for (std::size_t index = 0; index < Protocols.size(); ++index)
    {
        auto*& pcb = m_demultiplexer[index];
        pcb = raw_new_ip_type(IPADDR_TYPE_ANY, Protocols[index]);
        if (pcb == nullptr)
        {
            throw Exception(Error::CapacityExceeded);
        }
        // Both local interfaces use this hook. Only the peer interface needs
        // full TCP tuple ownership checks; the service interface owns its TCP.
        raw_recv(pcb, DemultiplexInput, this);
    }
}

void StackImpl::RemoveDemultiplexer() noexcept
{
    for (auto*& pcb : m_demultiplexer)
    {
        if (pcb != nullptr)
        {
            raw_remove(pcb);
            pcb = nullptr;
        }
    }
}

std::uint8_t
StackImpl::DemultiplexInput(void* context, raw_pcb*, pbuf* packet, const ip_addr_t*) noexcept
{
    auto& stack = *static_cast<StackImpl*>(context);
    const auto headerLength = ip_current_header_tot_len();
    const bool fromHost = ip_current_input_netif() == &stack.m_service.Native;
    if (headerLength <= packet->tot_len && packet->tot_len - headerLength >= TCP_HLEN &&
        CarriesTcp(packet, headerLength))
    {
        if (fromHost)
        {
            return 0;
        }
        std::array<std::uint8_t, 4> ports{};
        (void)pbuf_copy_partial(packet, ports.data(), ports.size(), headerLength);
        const auto remotePort = static_cast<std::uint16_t>((ports[0] << 8) | ports[1]);
        const auto localPort = static_cast<std::uint16_t>((ports[2] << 8) | ports[3]);
        if (stack.m_runtime->OwnsConnection(*ip_current_dest_addr(),
                                            localPort,
                                            *ip_current_src_addr(),
                                            remotePort,
                                            netif_get_index(&stack.m_node.Native)))
        {
            return 0;
        }
    }
    // Authenticated peer traffic that is not ours belongs to the host TCP stack.
    // Consume even on queue exhaustion: synthesizing an lwIP RST would break it.
    (void)stack.QueueOutput(fromHost ? PacketPath::HostNetwork : PacketPath::Host, packet);
    pbuf_free(packet);
    return 1;
}

namespace
{

constexpr std::size_t MaximumOutputBytes = 2U * 1024U * 1024U;

} // namespace

bool StackImpl::Input(PacketPath path, std::span<const std::uint8_t> packet)
{
    std::lock_guard lock(m_runtime->Mutex());
    RequireStarted();
    m_runtime->Poll();
    if ((path != PacketPath::Host && path != PacketPath::Peer) || packet.empty() ||
        packet.size() > std::numeric_limits<std::uint16_t>::max())
    {
        return false;
    }
    auto* buffer = pbuf_alloc(PBUF_RAW, static_cast<std::uint16_t>(packet.size()), PBUF_RAM);
    if (buffer == nullptr)
    {
        return false;
    }
    (void)pbuf_take(buffer, packet.data(), static_cast<std::uint16_t>(packet.size()));
    auto& interface = path == PacketPath::Host ? m_service.Native : m_node.Native;
    const auto error = interface.input(buffer, &interface);
    if (error != ERR_OK)
    {
        pbuf_free(buffer);
    }
    return error == ERR_OK;
}

err_t StackImpl::Output4(netif* interface, pbuf* packet, const ip4_addr_t*) noexcept
{
    return Output(interface, packet);
}

err_t StackImpl::Output6(netif* interface, pbuf* packet, const ip6_addr_t*) noexcept
{
    return Output(interface, packet);
}

err_t StackImpl::Output(netif* interface, pbuf* packet) noexcept
{
    const auto& binding = *static_cast<Interface*>(interface->state);
    return binding.Owner->QueueOutput(binding.Path, packet);
}

err_t StackImpl::QueueOutput(PacketPath path, pbuf* packet) noexcept
{
    if (m_discardOutput)
    {
        return ERR_OK;
    }
    if (packet->tot_len > MaximumOutputBytes - m_outputBytes)
    {
        return ERR_MEM;
    }
    try
    {
        OutputPacket output;
        output.Path = path;
        output.Bytes.resize(packet->tot_len);
        (void)pbuf_copy_partial(packet, output.Bytes.data(), packet->tot_len, 0);
        if (output.Bytes.size() >= IP6_HLEN && (output.Bytes.front() >> 4) == 6)
        {
            // Serialize the wire length from the flattened buffer. Upstream
            // reassembly removes the fragment header, but its cached IPv6 length
            // can disagree with the resulting pbuf chain. TCP consumes the chain;
            // a host stack consumes the wire header, so both must describe it.
            constexpr auto PayloadLengthOffset = offsetof(ip6_hdr, _plen);
            const auto payloadLength = output.Bytes.size() - IP6_HLEN;
            output.Bytes[PayloadLengthOffset] = static_cast<std::uint8_t>(payloadLength >> 8);
            output.Bytes[PayloadLengthOffset + 1] = static_cast<std::uint8_t>(payloadLength);
        }
        m_output.push_back(std::move(output));
        m_outputBytes += packet->tot_len;
        return ERR_OK;
    }
    catch (const std::bad_alloc&)
    {
        return ERR_MEM;
    }
}

std::vector<OutputPacket> StackImpl::TakeOutput(std::size_t maximumPackets)
{
    std::lock_guard lock(m_runtime->Mutex());
    std::vector<OutputPacket> result;
    result.reserve(std::min(maximumPackets, m_output.size()));
    while (!m_output.empty() && result.size() < maximumPackets)
    {
        m_outputBytes -= m_output.front().Bytes.size();
        result.push_back(std::move(m_output.front()));
        m_output.pop_front();
    }
    return result;
}

bool StackImpl::HasOutput(PacketPath path) const
{
    std::lock_guard lock(m_runtime->Mutex());
    return std::ranges::any_of(m_output,
                               [path](const OutputPacket& packet)
                               {
                                   return packet.Path == path;
                               });
}

void StackImpl::InvalidatePeerPackets()
{
    std::lock_guard lock(m_runtime->Mutex());
    RequireStarted();
    // Expiry can generate ICMP quoting an old fragment. Suppress that output
    // as well: its destination may now belong to a different authenticated node.
    m_discardOutput = true;
    m_runtime->ClearFragments();
    m_discardOutput = false;
    std::erase_if(m_output,
                  [this](const OutputPacket& packet)
                  {
                      if (packet.Path != PacketPath::Peer)
                      {
                          return false;
                      }
                      m_outputBytes -= packet.Bytes.size();
                      return true;
                  });
}

} // namespace tailgate::wgengine::netstack::impl
