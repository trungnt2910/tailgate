#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include <tailgate/base/EventLoop.h>
#include <tailgate/wgengine/magicsock/Connection.h>
#include <tailgate/wgengine/tstun/Device.h>

namespace tailgate::wgengine
{

struct EngineEventFailure
{
    tailgate::wgengine::magicsock::Connection::EventStatus Status =
        tailgate::wgengine::magicsock::Connection::EventStatus::Ready;
};

struct EngineWaitResult
{
    tailgate::base::EventWaitStatus Status = tailgate::base::EventWaitStatus::Events;
    std::vector<tailgate::types::nettype::UdpDatagram> Datagrams;
    std::vector<std::vector<std::uint8_t>> Packets;
    std::vector<EngineEventFailure> Failures;
    std::vector<tailgate::base::Event> PlatformEvents;
};

enum class PacketWriteResult
{
    Written,
    Queued,
    Dropped,
    Unavailable,
};

class Engine
{
public:
    virtual ~Engine();

    [[nodiscard]] virtual bool
    OpenPacketDevice(const tailgate::wgengine::tstun::DeviceOptions& options) = 0;
    [[nodiscard]] virtual PacketWriteResult WritePacket(std::vector<std::uint8_t> packet) = 0;
    [[nodiscard]] virtual EngineWaitResult Wait(std::size_t maximumEvents,
                                                std::size_t maximumDatagramsPerSocket,
                                                std::size_t maximumDatagramSize) = 0;
    [[nodiscard]] virtual EngineWaitResult Wait(const tailgate::base::WaitToken& waitToken,
                                                std::size_t maximumEvents,
                                                std::size_t maximumDatagramsPerSocket,
                                                std::size_t maximumDatagramSize) = 0;
    virtual void Wake() noexcept = 0;

protected:
    Engine() = default;
};

} // namespace tailgate::wgengine
