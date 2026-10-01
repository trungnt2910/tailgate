#pragma once

#include <tailgate/wgengine/wireguard/Router.h>

namespace tailgate::wgengine
{

// Delivery of encrypted packets is independent of the single router/counter/replay owner.
// Discovery remains scoped to each provider; a hosted endpoint is never a native proof.
class PacketPath
{
public:
    virtual ~PacketPath() = default;
    virtual void Send(const wireguard::WireGuardRouter::TransportPacket& packet) = 0;
};

} // namespace tailgate::wgengine
