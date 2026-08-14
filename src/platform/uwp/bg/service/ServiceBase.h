#pragma once

#include <cstdint>
#include <vector>

#include <tailgate/hosted/Protocol.h>
#include <tailgate/wgengine/wireguard/Router.h>

#include "service/IService.h"

namespace tailgate::uwp::bg::service
{

class ServiceBase : public IService
{
protected:
    static void AppendRelayFrame(std::vector<std::uint8_t>& output,
                                 const tailgate::hosted::Frame& frame);
    static void AppendTransportFrames(
        std::vector<std::uint8_t>& output,
        std::vector<tailgate::wgengine::wireguard::WireGuardRouter::TransportPacket> packets);
};

} // namespace tailgate::uwp::bg::service
