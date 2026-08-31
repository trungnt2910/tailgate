#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Networking.Vpn.h>

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
    [[nodiscard]] bool Open(const tailgate::wgengine::tstun::DeviceOptions& options) override;
    [[nodiscard]] tailgate::wgengine::tstun::DeviceReadResult
    TryRead(std::size_t maximumPacketSize) override;
    [[nodiscard]] tailgate::wgengine::tstun::DeviceIoResult
    TryWrite(const std::vector<std::uint8_t>& packet) override;
    void SetWriteInterest(bool enabled) override;
    void Close() noexcept override;
    [[nodiscard]] std::unique_ptr<tailgate::types::nettype::TcpSocket>
    OpenTransportSocket(const tailgate::types::nettype::TcpSocketOptions& options) override;

    [[nodiscard]] PacketQueueResult QueueInput(std::vector<std::uint8_t> packet);
    [[nodiscard]] std::vector<std::vector<std::uint8_t>> DrainOutput();
    [[nodiscard]] bool WriteInterest() const noexcept;
    void PrepareTransport(const winrt::Windows::Networking::Vpn::VpnChannel& channel);
    [[nodiscard]] bool HasTransportSocket() const;
    [[nodiscard]] winrt::Windows::Networking::Sockets::StreamSocket TransportSocket() const;
    void CloseTransport();
    void ResetTransport() noexcept;

private:
    static constexpr std::size_t MaximumPackets = 1024;
    static constexpr std::size_t MaximumBytes = 4U * 1024U * 1024U;

    mutable std::mutex m_mutex;
    std::deque<std::vector<std::uint8_t>> m_input;
    std::deque<std::vector<std::uint8_t>> m_output;
    std::size_t m_inputBytes = 0;
    std::size_t m_outputBytes = 0;
    bool m_open = false;
    bool m_writeInterest = false;
    winrt::Windows::Networking::Vpn::VpnChannel m_channel{nullptr};
    winrt::Windows::Networking::Sockets::StreamSocket m_transportSocket{nullptr};
};

} // namespace tailgate::uwp::bg
