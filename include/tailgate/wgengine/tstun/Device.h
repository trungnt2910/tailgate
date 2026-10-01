#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <tailgate/base/EventLoop.h>

namespace tailgate::wgengine::tstun
{

enum class DeviceIoResult
{
    Complete,
    WouldBlock,
    Closed,
};

struct DeviceReadResult
{
    DeviceIoResult Result = DeviceIoResult::WouldBlock;
    std::vector<std::uint8_t> Packet;
};

struct DeviceOptions
{
    std::string Name;
    tailgate::base::EventToken ReadinessToken;
};

class Device
{
public:
    virtual ~Device();

    [[nodiscard]] virtual bool Open(const DeviceOptions& options) = 0;
    [[nodiscard]] virtual DeviceReadResult TryRead(std::size_t maximumPacketSize) = 0;
    [[nodiscard]] virtual DeviceIoResult TryWrite(const std::vector<std::uint8_t>& packet) = 0;
    virtual void SetWriteInterest(bool enabled) = 0;
    virtual void Close() noexcept = 0;
};

} // namespace tailgate::wgengine::tstun
