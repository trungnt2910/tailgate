#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>

#include <tailgate/base/EventLoop.h>
#include <tailgate/base/Logger.h>
#include <tailgate/wgengine/Engine.h>
#include <tailgate/wgengine/magicsock/Connection.h>
#include <tailgate/wgengine/tstun/Device.h>

namespace tailgate::wgengine::impl
{

class EngineImpl final : public tailgate::wgengine::Engine
{
public:
    EngineImpl(tailgate::base::EventLoop& eventLoop,
               tailgate::wgengine::magicsock::Connection& connection,
               tailgate::wgengine::tstun::Device& device) noexcept;

    [[nodiscard]] bool
    OpenPacketDevice(const tailgate::wgengine::tstun::DeviceOptions& options) override;
    [[nodiscard]] PacketWriteResult WritePacket(std::vector<std::uint8_t> packet) override;

    [[nodiscard]] EngineWaitResult Wait(std::size_t maximumEvents,
                                        std::size_t maximumDatagramsPerSocket,
                                        std::size_t maximumDatagramSize) override;
    [[nodiscard]] EngineWaitResult Wait(const tailgate::base::WaitToken& waitToken,
                                        std::size_t maximumEvents,
                                        std::size_t maximumDatagramsPerSocket,
                                        std::size_t maximumDatagramSize) override;
    void Wake() noexcept override;

private:
    [[nodiscard]] bool QueuePacket(std::vector<std::uint8_t> packet);
    [[nodiscard]] tailgate::wgengine::tstun::DeviceIoResult FlushPackets();
    [[nodiscard]] bool ProcessDevice(const tailgate::base::Event& event,
                                     std::size_t maximumPackets,
                                     std::size_t maximumPacketSize,
                                     EngineWaitResult& result);

    static constexpr std::size_t MaximumPendingPackets = 1024;
    static constexpr std::size_t MaximumPendingBytes = 4U * 1024U * 1024U;

    tailgate::base::EventLoop& m_eventLoop;
    tailgate::wgengine::magicsock::Connection& m_connection;
    tailgate::wgengine::tstun::Device& m_device;
    tailgate::base::EventToken m_deviceToken;
    std::deque<std::vector<std::uint8_t>> m_pendingPackets;
    std::size_t m_pendingBytes = 0;
    bool m_deviceOpen = false;
    tailgate::base::Logger m_logger{"wgengine"};

    [[nodiscard]] EngineWaitResult Process(tailgate::base::EventWaitResult ready,
                                           std::size_t maximumDatagramsPerSocket,
                                           std::size_t maximumDatagramSize);
};

} // namespace tailgate::wgengine::impl
