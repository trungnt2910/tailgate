#include "PacketDevice.h"

#include <stdexcept>
#include <utility>

#include <winrt/Windows.Foundation.h>

#include "common/TcpSocketFactory.h"

namespace tailgate::uwp::bg
{

bool PacketDevice::Open(const tailgate::wgengine::tstun::DeviceOptions& options)
{
    std::lock_guard lock(m_mutex);
    if (m_open || options.ReadinessToken.Value == 0)
    {
        return false;
    }
    m_open = true;
    return true;
}

tailgate::wgengine::tstun::DeviceReadResult PacketDevice::TryRead(std::size_t)
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

std::unique_ptr<tailgate::types::nettype::TcpSocket>
PacketDevice::OpenTransportSocket(const tailgate::types::nettype::TcpSocketOptions& options)
{
    winrt::Windows::Networking::Sockets::StreamSocket socket;
    {
        std::lock_guard lock(m_mutex);
        if (!m_channel)
        {
            throw std::logic_error("The VPN packet device is not prepared for transport.");
        }
        m_transportSocket = winrt::Windows::Networking::Sockets::StreamSocket();
        m_channel.AssociateTransport(m_transportSocket, nullptr);
        socket = m_transportSocket;
    }
    return tailgate::uwp::TcpSocketFactory::ConnectTcpSocket(std::move(socket), options);
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
    return result;
}

bool PacketDevice::WriteInterest() const noexcept
{
    std::lock_guard lock(m_mutex);
    return m_writeInterest;
}

void PacketDevice::PrepareTransport(const winrt::Windows::Networking::Vpn::VpnChannel& channel)
{
    std::lock_guard lock(m_mutex);
    m_channel = channel;
    m_transportSocket = nullptr;
}

bool PacketDevice::HasTransportSocket() const
{
    std::lock_guard lock(m_mutex);
    return m_transportSocket != nullptr;
}

winrt::Windows::Networking::Sockets::StreamSocket PacketDevice::TransportSocket() const
{
    std::lock_guard lock(m_mutex);
    return m_transportSocket;
}

void PacketDevice::CloseTransport()
{
    std::lock_guard lock(m_mutex);
    if (m_transportSocket)
    {
        m_transportSocket.Close();
    }
}

void PacketDevice::ResetTransport() noexcept
{
    std::lock_guard lock(m_mutex);
    m_transportSocket = nullptr;
    m_channel = nullptr;
}

} // namespace tailgate::uwp::bg
