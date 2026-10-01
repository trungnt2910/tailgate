#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

#include <tailgate/wgengine/tstun/Device.h>

namespace tailgate::uwp::bg
{

enum class PacketQueueResult
{
    Complete,
    Full,
    Closed,
};

class PacketDevice final : public tailgate::wgengine::tstun::Device
{
public:
    explicit PacketDevice(tailgate::base::EventLoop& events) noexcept;
    [[nodiscard]] bool Open(const tailgate::wgengine::tstun::DeviceOptions& options) override;
    [[nodiscard]] tailgate::wgengine::tstun::DeviceReadResult
    TryRead(std::size_t maximumPacketSize) override;
    [[nodiscard]] tailgate::wgengine::tstun::DeviceIoResult
    TryWrite(const std::vector<std::uint8_t>& packet) override;
    void SetWriteInterest(bool enabled) override;
    void Close() noexcept override;

    [[nodiscard]] PacketQueueResult QueueInput(std::vector<std::uint8_t> packet);
    [[nodiscard]] std::vector<std::vector<std::uint8_t>> DrainOutput();
    [[nodiscard]] bool WriteInterest() const noexcept;
    [[nodiscard]] bool HasOutput() const noexcept;

private:
    static constexpr std::size_t MaximumPackets = 1024;
    static constexpr std::size_t MaximumBytes = 4U * 1024U * 1024U;

    tailgate::base::EventLoop& m_events;
    tailgate::base::EventToken m_token;
    mutable std::mutex m_mutex;
    std::deque<std::vector<std::uint8_t>> m_input;
    std::deque<std::vector<std::uint8_t>> m_output;
    std::size_t m_inputBytes = 0;
    std::size_t m_outputBytes = 0;
    bool m_open = false;
    bool m_writeInterest = false;
};

} // namespace tailgate::uwp::bg
