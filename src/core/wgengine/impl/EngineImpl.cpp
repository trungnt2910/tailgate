#include "EngineImpl.h"

#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <utility>

namespace tailgate::wgengine::impl
{

EngineImpl::EngineImpl(tailgate::base::EventLoop& eventLoop,
                       tailgate::wgengine::magicsock::Connection& connection,
                       tailgate::wgengine::tstun::Device& device) noexcept
    : m_eventLoop(eventLoop), m_connection(connection), m_device(device)
{
}

bool EngineImpl::OpenPacketDevice(const tailgate::wgengine::tstun::DeviceOptions& options)
{
    if (m_deviceOpen || options.ReadinessToken.Value == 0)
    {
        return false;
    }
    if (!m_device.Open(options))
    {
        return false;
    }
    m_deviceOpen = true;
    m_deviceToken = options.ReadinessToken;
    m_logger.LogDebug("opened packet device name={}", options.Name);
    return true;
}

PacketWriteResult EngineImpl::WritePacket(std::vector<std::uint8_t> packet)
{
    if (!m_deviceOpen)
    {
        return PacketWriteResult::Unavailable;
    }
    if (!m_pendingPackets.empty())
    {
        return QueuePacket(std::move(packet)) ? PacketWriteResult::Queued
                                              : PacketWriteResult::Dropped;
    }
    const tailgate::wgengine::tstun::DeviceIoResult written = m_device.TryWrite(packet);
    if (written == tailgate::wgengine::tstun::DeviceIoResult::Complete)
    {
        return PacketWriteResult::Written;
    }
    if (written == tailgate::wgengine::tstun::DeviceIoResult::Closed)
    {
        return PacketWriteResult::Unavailable;
    }
    return QueuePacket(std::move(packet)) ? PacketWriteResult::Queued : PacketWriteResult::Dropped;
}

EngineWaitResult EngineImpl::Wait(std::size_t maximumEvents,
                                  std::size_t maximumDatagramsPerSocket,
                                  std::size_t maximumDatagramSize)
{
    return Process(m_eventLoop.Wait(maximumEvents), maximumDatagramsPerSocket, maximumDatagramSize);
}

EngineWaitResult EngineImpl::Wait(const tailgate::base::WaitToken& waitToken,
                                  std::size_t maximumEvents,
                                  std::size_t maximumDatagramsPerSocket,
                                  std::size_t maximumDatagramSize)
{
    return Process(
        m_eventLoop.Wait(waitToken, maximumEvents), maximumDatagramsPerSocket, maximumDatagramSize);
}

EngineWaitResult EngineImpl::Process(tailgate::base::EventWaitResult ready,
                                     std::size_t maximumDatagramsPerSocket,
                                     std::size_t maximumDatagramSize)
{
    EngineWaitResult result{
        .Status = ready.Status,
        .Datagrams = {},
        .Packets = {},
        .Failures = {},
        .PlatformEvents = {},
    };
    for (const tailgate::base::Event& event : ready.Events)
    {
        tailgate::wgengine::magicsock::Connection::EventResult processed =
            m_connection.ProcessEvent(event, maximumDatagramsPerSocket, maximumDatagramSize);
        if (!processed.Handled)
        {
            if (!ProcessDevice(event, maximumDatagramsPerSocket, maximumDatagramSize, result))
            {
                result.PlatformEvents.push_back(event);
            }
            continue;
        }
        result.Datagrams.insert(result.Datagrams.end(),
                                std::make_move_iterator(processed.Datagrams.begin()),
                                std::make_move_iterator(processed.Datagrams.end()));
        if (processed.Status != tailgate::wgengine::magicsock::Connection::EventStatus::Ready)
        {
            result.Failures.push_back(EngineEventFailure{
                .Status = processed.Status,
            });
        }
    }
    return result;
}

bool EngineImpl::QueuePacket(std::vector<std::uint8_t> packet)
{
    while (!m_pendingPackets.empty() && (m_pendingPackets.size() >= MaximumPendingPackets ||
                                         m_pendingBytes + packet.size() > MaximumPendingBytes))
    {
        m_pendingBytes -= m_pendingPackets.front().size();
        m_pendingPackets.pop_front();
        m_logger.LogWarning("packet-device queue limit reached; dropping oldest packet");
    }
    if (packet.size() > MaximumPendingBytes)
    {
        m_logger.LogWarning("packet exceeds packet-device queue limit; dropping packet");
        return false;
    }
    m_pendingBytes += packet.size();
    m_pendingPackets.push_back(std::move(packet));
    m_device.SetWriteInterest(true);
    return true;
}

tailgate::wgengine::tstun::DeviceIoResult EngineImpl::FlushPackets()
{
    while (!m_pendingPackets.empty())
    {
        const tailgate::wgengine::tstun::DeviceIoResult written =
            m_device.TryWrite(m_pendingPackets.front());
        if (written != tailgate::wgengine::tstun::DeviceIoResult::Complete)
        {
            return written;
        }
        m_pendingBytes -= m_pendingPackets.front().size();
        m_pendingPackets.pop_front();
    }
    m_device.SetWriteInterest(false);
    return tailgate::wgengine::tstun::DeviceIoResult::Complete;
}

bool EngineImpl::ProcessDevice(const tailgate::base::Event& event,
                               std::size_t maximumPackets,
                               std::size_t maximumPacketSize,
                               EngineWaitResult& result)
{
    if (!m_deviceOpen || event.Token != m_deviceToken)
    {
        return false;
    }
    if (tailgate::base::HasReadiness(event.Readiness, tailgate::base::EventReadiness::Error))
    {
        throw std::runtime_error("packet device reported an I/O error");
    }
    if (tailgate::base::HasReadiness(event.Readiness, tailgate::base::EventReadiness::Closed))
    {
        throw std::runtime_error("packet device closed");
    }
    if (tailgate::base::HasReadiness(event.Readiness, tailgate::base::EventReadiness::Writable) &&
        FlushPackets() == tailgate::wgengine::tstun::DeviceIoResult::Closed)
    {
        throw std::runtime_error("packet device closed during write");
    }
    if (!tailgate::base::HasReadiness(event.Readiness, tailgate::base::EventReadiness::Readable))
    {
        return true;
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
            throw std::runtime_error("packet device closed during read");
        }
        result.Packets.push_back(std::move(packet.Packet));
    }
    return true;
}

void EngineImpl::Wake() noexcept
{
    m_eventLoop.Wake();
}

} // namespace tailgate::wgengine::impl
