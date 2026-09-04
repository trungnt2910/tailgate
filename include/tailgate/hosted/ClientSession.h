#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/wgengine/tstun/Device.h>

namespace tailgate::hosted
{

enum class PacketDeviceStatus
{
    Ready,
    Dropped,
    Closed,
};

struct ClientSessionProcessResult
{
    PacketDeviceStatus DeviceStatus = PacketDeviceStatus::Ready;
    std::vector<std::uint8_t> RemoteOutput;
    std::optional<DiscoPong> Pong;
    bool NetworkMapChanged = false;
    bool DataPathReady = false;
};

class ClientSession
{
public:
    virtual ~ClientSession();

    [[nodiscard]] virtual bool
    OpenPacketDevice(const tailgate::wgengine::tstun::DeviceOptions& options) = 0;
    [[nodiscard]] virtual ClientSessionProcessResult
    ProcessPacketDevice(std::size_t maximumPackets, std::size_t maximumPacketSize) = 0;
    [[nodiscard]] virtual ClientSessionProcessResult ProcessFrame(const Frame& frame) = 0;
    [[nodiscard]] virtual PacketDeviceStatus
    WritePacketDevice(std::vector<std::uint8_t> packet) = 0;
    [[nodiscard]] virtual PacketDeviceStatus FlushPacketDevice() = 0;
    virtual void ClosePacketDevice() noexcept = 0;

protected:
    ClientSession() = default;
};

} // namespace tailgate::hosted
