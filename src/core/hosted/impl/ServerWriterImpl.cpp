#include "ServerWriterImpl.h"

#include <algorithm>
#include <chrono>
#include <system_error>
#include <vector>

namespace tailgate::hosted::impl
{
namespace
{

constexpr std::chrono::seconds HeartbeatInterval{20};
constexpr std::size_t MaximumPacketBatch = 64;
constexpr tailgate::base::EventToken PacketReady{.Value = 1};

} // namespace

ServerWriterImpl::ServerWriterImpl(tailgate::base::EventLoop& eventLoop,
                                   tailgate::base::TimeProvider& timeProvider,
                                   tailgate::wgengine::tstun::Device& device) noexcept
    : m_eventLoop(eventLoop), m_timeProvider(timeProvider), m_device(device)
{
}

void ServerWriterImpl::Run(ServerSession& session,
                           tailgate::base::ByteStream& stream,
                           std::mutex& streamMutex,
                           const std::atomic<bool>& stopping)
{
    if (!m_device.Open(
            tailgate::wgengine::tstun::DeviceOptions{.Name = {}, .ReadinessToken = PacketReady}))
    {
        throw ServerWriterOpenError();
    }
    try
    {
        Process(session, stream, streamMutex, stopping);
    }
    catch (...)
    {
        m_device.Close();
        throw;
    }
    m_device.Close();
}

void ServerWriterImpl::Process(ServerSession& session,
                               tailgate::base::ByteStream& stream,
                               std::mutex& streamMutex,
                               const std::atomic<bool>& stopping)
{
    auto heartbeat = m_timeProvider.Now() + HeartbeatInterval;
    while (!stopping)
    {
        const auto deadline = std::min(heartbeat, session.NextPumpDeadline().value_or(heartbeat));
        const auto timeout = m_timeProvider.At(deadline);
        const auto ready = m_eventLoop.Wait(*timeout, 1);
        if (stopping)
        {
            break;
        }
        std::vector<Frame> frames;
        {
            std::lock_guard lock(m_outputMutex);
            while (!m_output.empty())
            {
                m_outputBytes -= m_output.front().Payload().size();
                frames.push_back(std::move(m_output.front()));
                m_output.pop_front();
            }
        }
        if (auto pump = session.TakeDuePump())
        {
            frames.push_back(std::move(*pump));
        }
        if (m_timeProvider.Now() >= heartbeat)
        {
            frames.push_back(session.BuildHeartbeat());
            heartbeat = m_timeProvider.Now() + HeartbeatInterval;
        }
        bool closed = false;
        std::size_t batchBytes = 0;
        // Deadlines are checked even when peer packets are continuously ready.
        for (const auto& event : ready.Events)
        {
            if (event.Token != PacketReady)
            {
                continue;
            }
            closed = tailgate::base::HasReadiness(event.Readiness,
                                                  tailgate::base::EventReadiness::Closed |
                                                      tailgate::base::EventReadiness::Error);
            if (!tailgate::base::HasReadiness(event.Readiness,
                                              tailgate::base::EventReadiness::Readable))
            {
                continue;
            }
            for (std::size_t count = 0; count < MaximumPacketBatch; ++count)
            {
                auto packet = m_device.TryRead(Frame::MaximumPayloadSize);
                if (packet.Result == tailgate::wgengine::tstun::DeviceIoResult::WouldBlock)
                {
                    break;
                }
                if (packet.Result == tailgate::wgengine::tstun::DeviceIoResult::Closed)
                {
                    closed = true;
                    break;
                }
                batchBytes += packet.Packet.size();
                frames.push_back(session.BuildServerPacket(std::move(packet.Packet)));
                heartbeat = m_timeProvider.Now() + HeartbeatInterval;
                if (batchBytes >= Frame::MaximumPayloadSize)
                {
                    break;
                }
            }
        }
        if (!frames.empty())
        {
            std::lock_guard lock(streamMutex);
            stream.WriteAll(Frame::EncodeAll(frames));
        }
        if (closed)
        {
            break;
        }
    }
}

void ServerWriterImpl::Post(Frame frame)
{
    constexpr std::size_t MaximumControlFrames = 256;
    constexpr std::size_t MaximumControlBytes = 1024U * 1024U;
    {
        std::lock_guard lock(m_outputMutex);
        if (m_output.size() >= MaximumControlFrames ||
            frame.Payload().size() > MaximumControlBytes - m_outputBytes)
        {
            throw std::system_error(std::make_error_code(std::errc::no_buffer_space));
        }
        m_outputBytes += frame.Payload().size();
        m_output.push_back(std::move(frame));
    }
    Wake();
}

void ServerWriterImpl::Wake() noexcept
{
    m_eventLoop.Wake();
}

} // namespace tailgate::hosted::impl
