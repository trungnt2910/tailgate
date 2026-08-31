#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>

#include <tailgate/base/Logger.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/ClientSession.h>
#include <tailgate/wgengine/tstun/Device.h>

namespace tailgate::hosted::impl
{

class ClientSessionImpl final : public tailgate::hosted::ClientSession
{
public:
    ClientSessionImpl(tailgate::hosted::Client& client,
                      tailgate::wgengine::tstun::Device& device) noexcept;

    [[nodiscard]] bool
    OpenPacketDevice(const tailgate::wgengine::tstun::DeviceOptions& options) override;
    [[nodiscard]] tailgate::hosted::ClientSessionProcessResult
    ProcessPacketDevice(std::size_t maximumPackets, std::size_t maximumPacketSize) override;
    [[nodiscard]] tailgate::hosted::ClientSessionProcessResult
    ProcessFrame(const tailgate::hosted::Frame& frame) override;
    [[nodiscard]] tailgate::hosted::PacketDeviceStatus
    WritePacketDevice(std::vector<std::uint8_t> packet) override;
    [[nodiscard]] tailgate::hosted::PacketDeviceStatus FlushPacketDevice() override;
    void ClosePacketDevice() noexcept override;

private:
    [[nodiscard]] bool QueuePacket(std::vector<std::uint8_t> packet);
    void UpdateWriteInterest();

    static constexpr std::size_t MaximumPendingPackets = 1024;
    static constexpr std::size_t MaximumPendingBytes = 4U * 1024U * 1024U;

    tailgate::hosted::Client& m_client;
    tailgate::wgengine::tstun::Device& m_device;
    std::deque<std::vector<std::uint8_t>> m_pendingPackets;
    std::size_t m_pendingBytes = 0;
    bool m_open = false;
    tailgate::base::Logger m_logger{"hosted-session"};
};

} // namespace tailgate::hosted::impl
