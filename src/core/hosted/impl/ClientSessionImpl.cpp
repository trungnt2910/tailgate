#include "ClientSessionImpl.h"

#include <utility>

namespace tailgate::hosted::impl
{

ClientSessionImpl::ClientSessionImpl(tailgate::hosted::Client& client,
                                     tailgate::wgengine::tstun::Device& device) noexcept
    : m_client(client), m_device(device)
{
}

bool ClientSessionImpl::OpenPacketDevice(const tailgate::wgengine::tstun::DeviceOptions& options)
{
    if (m_open || !m_device.Open(options))
    {
        return false;
    }
    m_open = true;
    return true;
}

tailgate::hosted::ClientSessionProcessResult
ClientSessionImpl::ProcessPacketDevice(std::size_t maximumPackets, std::size_t maximumPacketSize)
{
    tailgate::hosted::ClientSessionProcessResult result;
    if (!m_open)
    {
        result.DeviceStatus = tailgate::hosted::PacketDeviceStatus::Closed;
        return result;
    }
    for (std::size_t index = 0; index < maximumPackets; ++index)
    {
        tailgate::wgengine::tstun::DeviceReadResult packet = m_device.TryRead(maximumPacketSize);
        if (packet.Result == tailgate::wgengine::tstun::DeviceIoResult::WouldBlock)
        {
            break;
        }
        if (packet.Result == tailgate::wgengine::tstun::DeviceIoResult::Closed)
        {
            result.DeviceStatus = tailgate::hosted::PacketDeviceStatus::Closed;
            break;
        }
        std::vector<std::uint8_t> remote = m_client.Encapsulate(packet.Packet);
        result.RemoteOutput.insert(result.RemoteOutput.end(), remote.begin(), remote.end());
    }
    return result;
}

tailgate::hosted::ClientSessionProcessResult
ClientSessionImpl::ProcessFrame(const tailgate::hosted::Frame& frame)
{
    tailgate::hosted::ClientProcessResult processed = m_client.Process(frame);
    tailgate::hosted::ClientSessionProcessResult result{
        .DeviceStatus = tailgate::hosted::PacketDeviceStatus::Ready,
        .RemoteOutput = std::move(processed.RemoteOutput),
        .Pong = std::move(processed.Pong),
        .NetworkMapChanged = processed.NetworkMapChanged,
    };
    for (std::vector<std::uint8_t>& packet : processed.LocalPackets)
    {
        const tailgate::hosted::PacketDeviceStatus written = WritePacketDevice(std::move(packet));
        if (written != tailgate::hosted::PacketDeviceStatus::Ready)
        {
            result.DeviceStatus = written;
            break;
        }
    }
    return result;
}

tailgate::hosted::PacketDeviceStatus ClientSessionImpl::FlushPacketDevice()
{
    while (!m_pendingPackets.empty())
    {
        const tailgate::wgengine::tstun::DeviceIoResult written =
            m_device.TryWrite(m_pendingPackets.front());
        if (written == tailgate::wgengine::tstun::DeviceIoResult::WouldBlock)
        {
            UpdateWriteInterest();
            return tailgate::hosted::PacketDeviceStatus::Ready;
        }
        if (written == tailgate::wgengine::tstun::DeviceIoResult::Closed)
        {
            return tailgate::hosted::PacketDeviceStatus::Closed;
        }
        m_pendingBytes -= m_pendingPackets.front().size();
        m_pendingPackets.pop_front();
    }
    UpdateWriteInterest();
    return tailgate::hosted::PacketDeviceStatus::Ready;
}

void ClientSessionImpl::ClosePacketDevice() noexcept
{
    m_pendingPackets.clear();
    m_pendingBytes = 0;
    m_open = false;
    m_device.Close();
}

bool ClientSessionImpl::QueuePacket(std::vector<std::uint8_t> packet)
{
    while (!m_pendingPackets.empty() && (m_pendingPackets.size() >= MaximumPendingPackets ||
                                         m_pendingBytes + packet.size() > MaximumPendingBytes))
    {
        m_logger.LogWarning("local packet queue limit reached; dropping oldest packet");
        m_pendingBytes -= m_pendingPackets.front().size();
        m_pendingPackets.pop_front();
    }
    if (packet.size() > MaximumPendingBytes)
    {
        m_logger.LogWarning("local packet exceeds queue byte limit; dropping packet");
        return false;
    }
    m_pendingBytes += packet.size();
    m_pendingPackets.push_back(std::move(packet));
    UpdateWriteInterest();
    return true;
}

tailgate::hosted::PacketDeviceStatus
ClientSessionImpl::WritePacketDevice(std::vector<std::uint8_t> packet)
{
    if (!m_open)
    {
        return tailgate::hosted::PacketDeviceStatus::Closed;
    }
    if (!m_pendingPackets.empty())
    {
        return QueuePacket(std::move(packet)) ? tailgate::hosted::PacketDeviceStatus::Ready
                                              : tailgate::hosted::PacketDeviceStatus::Dropped;
    }
    const tailgate::wgengine::tstun::DeviceIoResult written = m_device.TryWrite(packet);
    if (written == tailgate::wgengine::tstun::DeviceIoResult::Closed)
    {
        return tailgate::hosted::PacketDeviceStatus::Closed;
    }
    if (written == tailgate::wgengine::tstun::DeviceIoResult::WouldBlock)
    {
        return QueuePacket(std::move(packet)) ? tailgate::hosted::PacketDeviceStatus::Ready
                                              : tailgate::hosted::PacketDeviceStatus::Dropped;
    }
    return tailgate::hosted::PacketDeviceStatus::Ready;
}

void ClientSessionImpl::UpdateWriteInterest()
{
    if (m_open)
    {
        m_device.SetWriteInterest(!m_pendingPackets.empty());
    }
}

} // namespace tailgate::hosted::impl
