#include "ServiceBase.h"

#include <utility>

namespace tailgate::uwp::bg::service
{

void ServiceBase::AppendRelayFrame(std::vector<std::uint8_t>& output,
                                   const tailgate::hosted::Frame& frame)
{
    std::vector<std::uint8_t> encoded = tailgate::hosted::Encode(frame);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

void ServiceBase::AppendTransportFrames(
    std::vector<std::uint8_t>& output,
    std::vector<tailgate::wgengine::wireguard::WireGuardRouter::TransportPacket> packets)
{
    for (auto& packet : packets)
    {
        AppendRelayFrame(
            output,
            tailgate::hosted::Frame{
                .Type = tailgate::hosted::MessageType::ClientPacket,
                .Payload = tailgate::hosted::EncodePeerPacket(tailgate::hosted::PeerPacket{
                    .Peer = packet.Peer,
                    .Payload = std::move(packet.Payload),
                    .Control = packet.Control,
                }),
            });
    }
}

} // namespace tailgate::uwp::bg::service
