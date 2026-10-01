#pragma once

#include <cstdint>
#include <deque>
#include <mutex>

#include <winrt/Windows.Networking.Vpn.h>

#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"
#include "manager/ChannelPolicy.h"
#include "tstun/LoopbackTransport.h"

namespace tailgate::uwp::bg
{

// RS2 channel boundary. Windows buffers never escape their callback; the worker only
// exchanges owned packets. The wake transport is independent of all network sockets.
class ChannelAdapter final
{
public:
    ChannelAdapter(std::shared_ptr<tailgate::base::EventLoop> events,
                   tailgate::base::TimeProvider& time);
    void Open(const winrt::Windows::Networking::Vpn::VpnChannel& channel,
              std::stop_token cancellation);
    void Start(const winrt::Windows::Networking::Vpn::VpnChannel& channel,
               const manager::ChannelPolicy& policy);
    void Close();
    [[nodiscard]] bool Failed() const noexcept;
    void Encapsulate(const winrt::Windows::Networking::Vpn::VpnPacketBufferList& packets,
                     const winrt::Windows::Networking::Vpn::VpnPacketBufferList& output);
    void Decapsulate(const winrt::Windows::Networking::Vpn::VpnChannel& channel,
                     const winrt::Windows::Networking::Vpn::VpnPacketBufferList& packets);
    void KeepAlive(const winrt::Windows::Networking::Vpn::VpnChannel& channel,
                   winrt::Windows::Networking::Vpn::VpnPacketBuffer& packet);
    [[nodiscard]] std::vector<std::vector<std::uint8_t>> TakeInput(std::size_t maximumPackets);
    void QueueOutput(std::vector<std::vector<std::uint8_t>> packets);

private:
    static constexpr std::size_t MaximumPackets = 1024;
    static constexpr std::size_t MaximumBytes = 4U * 1024U * 1024U;
    static constexpr std::size_t MaximumPacketsPerTurn = 64;
    std::shared_ptr<tailgate::base::EventLoop> m_events;
    LoopbackTransport m_loopback;
    std::mutex m_mutex;
    std::deque<std::vector<std::uint8_t>> m_input;
    std::deque<std::vector<std::uint8_t>> m_output;
    std::size_t m_inputBytes = 0;
    std::size_t m_outputBytes = 0;
    bool m_enabled = false;
    bool m_started = false;
    tailgate::base::Logger m_logger{"uwp-channel"};
};

} // namespace tailgate::uwp::bg
