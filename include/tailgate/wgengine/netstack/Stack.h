#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include <tailgate/base/TimeProvider.h>
#include <tailgate/net/IpAddress.h>
#include <tailgate/wgengine/netstack/Stream.h>

namespace tailgate::wgengine::netstack
{

enum class PacketPath
{
    Host,
    Peer,
    // Output only: an intercepted host datagram proved not to be TCP after
    // reassembly. Resume its normal outbound path, never inject it as a reply.
    HostNetwork,
};

struct InterfaceAddresses
{
    net::IpAddress Ipv4;
    std::optional<net::IpAddress> Ipv6;
};

struct Configuration
{
    InterfaceAddresses Service;
    InterfaceAddresses Node;
};

struct TcpEndpoint
{
    net::IpAddress Address;
    std::uint16_t Port = 0;
};

struct OutputPacket
{
    PacketPath Path = PacketPath::Host;
    std::vector<std::uint8_t> Bytes;
};

class Stack
{
public:
    virtual ~Stack();
    virtual void Start(const Configuration& configuration) = 0;
    virtual void Stop() noexcept = 0;
    // Endpoint ownership changed: discard partial datagrams and queued peer-bound
    // packets without closing unaffected TCP connections. Their TCP retransmission
    // state remains authoritative; stale plaintext must not reach a new IP owner.
    // The caller must cancel connections belonging to retired peers first.
    virtual void InvalidatePeerPackets() = 0;
    virtual void Listen(const TcpEndpoint& endpoint) = 0;
    [[nodiscard]] virtual std::unique_ptr<Stream> Connect(const TcpEndpoint& endpoint) = 0;
    [[nodiscard]] virtual std::unique_ptr<Stream> TakeAccepted() = 0;
    // The caller authenticates peer identity and restricts intercepted host traffic.
    [[nodiscard]] virtual bool Input(PacketPath path, std::span<const std::uint8_t> packet) = 0;
    [[nodiscard]] virtual std::vector<OutputPacket> TakeOutput(std::size_t maximumPackets) = 0;
    [[nodiscard]] virtual bool HasOutput(PacketPath path) const = 0;
    virtual void Poll() = 0;
    [[nodiscard]] virtual std::optional<base::TimeProvider::TimePoint> NextDeadline() const = 0;
};

} // namespace tailgate::wgengine::netstack
