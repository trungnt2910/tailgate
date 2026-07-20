#pragma once

#include <cstdint>
#include <vector>

#include <tailgate/protocol/WireGuardRouter.h>
#include <tailgate/relay/RelayProtocol.h>

#include "service/IService.h"

namespace tailgate::uwp::bg::service
{

class ServiceBase : public IService
{
protected:
    static void AppendRelayFrame(std::vector<std::uint8_t>& output, const relay::Frame& frame);
    static void
    AppendTransportFrames(std::vector<std::uint8_t>& output,
                          std::vector<protocol::WireGuardRouter::TransportPacket> packets);
};

} // namespace tailgate::uwp::bg::service
