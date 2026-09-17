#pragma once

#include <optional>
#include <span>
#include <vector>

#include <tailgate/base/TimeProvider.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::ipn::ipnlocal
{

struct ServicePacket
{
    // No peer means deliver to the local host. Peer identity is selected from
    // the authenticated netmap, never from a WebDAV request or a relay envelope.
    std::optional<crypto::Bytes32> Peer;
    std::vector<std::uint8_t> Bytes;
    bool ForwardFromHost = false;
};

class LocalServices
{
public:
    virtual ~LocalServices();
    virtual void SetNetworkConfig(const types::netmap::NetworkConfig& config) = 0;
    virtual void Stop() noexcept = 0;
    // True means consumed, including rejected local-service packets.
    [[nodiscard]] virtual bool HandleHostPacket(std::span<const std::uint8_t> packet) = 0;
    [[nodiscard]] virtual bool HandlePeerPacket(const crypto::Bytes32& authenticatedPeer,
                                                std::span<const std::uint8_t> packet) = 0;
    virtual void Poll() = 0;
    [[nodiscard]] virtual std::vector<ServicePacket> TakeOutput(std::size_t maximumPackets) = 0;
    [[nodiscard]] virtual std::optional<base::TimeProvider::TimePoint> NextDeadline() const = 0;
};

} // namespace tailgate::ipn::ipnlocal
