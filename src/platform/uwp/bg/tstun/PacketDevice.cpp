#include "PacketDevice.h"

#include <system_error>
#include <utility>

namespace tailgate::uwp::bg
{

PacketDevice::PacketDevice(tailgate::base::EventLoop& events) noexcept : m_events(events)
{
}

bool PacketDevice::Open(const tailgate::wgengine::tstun::DeviceOptions& options)
{
    std::lock_guard lock(m_mutex);
    if (m_open || options.ReadinessToken.Value == 0)
    {
        return false;
    }
    m_open = true;
    m_token = options.ReadinessToken;
    return true;
}

tailgate::wgengine::tstun::DeviceReadResult PacketDevice::TryRead(std::size_t maximumPacketSize)
{
    std::lock_guard lock(m_mutex);
    if (!m_open)
    {
        return tailgate::wgengine::tstun::DeviceReadResult{
            .Result = tailgate::wgengine::tstun::DeviceIoResult::Closed,
            .Packet = {},
        };
    }
    if (m_input.empty())
    {
        return {};
    }
    std::vector<std::uint8_t> packet = std::move(m_input.front());
    m_input.pop_front();
    m_inputBytes -= packet.size();
    if (!m_input.empty())
    {
        m_events.Post({.Token = m_token, .Readiness = tailgate::base::EventReadiness::Readable});
    }
    if (packet.size() > maximumPacketSize)
    {
        throw std::system_error(std::make_error_code(std::errc::message_size));
    }
    return tailgate::wgengine::tstun::DeviceReadResult{
        .Result = tailgate::wgengine::tstun::DeviceIoResult::Complete,
        .Packet = std::move(packet),
    };
}

tailgate::wgengine::tstun::DeviceIoResult
PacketDevice::TryWrite(const std::vector<std::uint8_t>& packet)
{
    std::lock_guard lock(m_mutex);
    if (!m_open)
    {
        return tailgate::wgengine::tstun::DeviceIoResult::Closed;
    }
    if (m_output.size() >= MaximumPackets || m_outputBytes + packet.size() > MaximumBytes)
    {
        return tailgate::wgengine::tstun::DeviceIoResult::WouldBlock;
    }
    m_outputBytes += packet.size();
    m_output.push_back(packet);
    return tailgate::wgengine::tstun::DeviceIoResult::Complete;
}

void PacketDevice::SetWriteInterest(bool enabled)
{
    std::lock_guard lock(m_mutex);
    if (m_open && enabled && !m_writeInterest && m_output.size() < MaximumPackets &&
        m_outputBytes < MaximumBytes)
    {
        m_events.Post({.Token = m_token, .Readiness = tailgate::base::EventReadiness::Writable});
    }
    m_writeInterest = enabled;
}

void PacketDevice::Close() noexcept
{
    std::lock_guard lock(m_mutex);
    m_input.clear();
    m_output.clear();
    m_inputBytes = 0;
    m_outputBytes = 0;
    m_open = false;
    m_writeInterest = false;
}

PacketQueueResult PacketDevice::QueueInput(std::vector<std::uint8_t> packet)
{
    std::lock_guard lock(m_mutex);
    if (!m_open)
    {
        return PacketQueueResult::Closed;
    }
    if (m_input.size() >= MaximumPackets || m_inputBytes + packet.size() > MaximumBytes)
    {
        return PacketQueueResult::Full;
    }
    m_inputBytes += packet.size();
    m_input.push_back(std::move(packet));
    m_events.Post({.Token = m_token, .Readiness = tailgate::base::EventReadiness::Readable});
    return PacketQueueResult::Complete;
}

std::vector<std::vector<std::uint8_t>> PacketDevice::DrainOutput()
{
    std::lock_guard lock(m_mutex);
    std::vector<std::vector<std::uint8_t>> result;
    result.reserve(m_output.size());
    while (!m_output.empty())
    {
        result.push_back(std::move(m_output.front()));
        m_output.pop_front();
    }
    m_outputBytes = 0;
    if (m_open && m_writeInterest && !result.empty())
    {
        m_events.Post({.Token = m_token, .Readiness = tailgate::base::EventReadiness::Writable});
    }
    return result;
}

bool PacketDevice::WriteInterest() const noexcept
{
    std::lock_guard lock(m_mutex);
    return m_writeInterest;
}

bool PacketDevice::HasOutput() const noexcept
{
    std::lock_guard lock(m_mutex);
    return !m_output.empty();
}

} // namespace tailgate::uwp::bg
