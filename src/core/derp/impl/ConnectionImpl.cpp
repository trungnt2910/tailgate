#include "ConnectionImpl.h"

#include <algorithm>
#include <chrono>
#include <exception>
#include <iterator>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <tailgate/base/EventLoop.h>
#include <tailgate/derp/Client.h>
#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::derp::impl
{

ConnectionImpl::ConnectionImpl(
    tailgate::derp::ConnectionOptions options,
    std::shared_ptr<tailgate::types::nettype::TcpSocketFactory> socketFactory,
    tailgate::base::TimeProvider& timeProvider,
    std::shared_ptr<tailgate::base::EventLoop> eventLoop)
    : m_options(std::move(options)),
      m_socketFactory(std::move(socketFactory)),
      m_timeProvider(timeProvider),
      m_eventLoop(std::move(eventLoop)),
      m_nextReconnect(m_timeProvider.Now())
{
    m_enabled = m_options.Enabled;
    Maintain();
}

ConnectionImpl::~ConnectionImpl()
{
    Disconnect();
}

void ConnectionImpl::Connect()
{
    if (!m_dial)
    {
        m_dial = std::make_unique<DialOperation>(m_options, m_socketFactory, m_eventLoop);
    }
    auto result = m_dial->TakeResult();
    if (!result)
    {
        return;
    }
    m_dial.reset();
    if (result->Error)
    {
        std::rethrow_exception(result->Error);
    }
    m_socket = std::move(result->Socket);
    m_client = std::move(result->Client);
    // Register readiness only after ownership has transferred to the event loop.
    m_socket->SetNonBlocking(true);
    m_reconnectDelay = InitialReconnectDelay;
    m_nextReconnect = tailgate::base::TimeProvider::TimePoint::max();
    FlushOutgoing();
    UpdateWriteInterest();
    m_logger.LogInfo("connected host={} preferred={}", m_options.Host, m_options.Preferred ? 1 : 0);
}

void ConnectionImpl::Disconnect() noexcept
{
    m_dial.reset();
    m_client.reset();
    if (m_socket)
    {
        m_socket->Close();
        m_socket.reset();
    }
}

void ConnectionImpl::ScheduleReconnect() noexcept
{
    Disconnect();
    m_nextReconnect = m_timeProvider.Now() + m_reconnectDelay;
    m_reconnectDelay = std::min(m_reconnectDelay * 2, MaximumReconnectDelay);
}

void ConnectionImpl::SetEnabled(bool enabled)
{
    if (m_enabled == enabled)
    {
        return;
    }
    m_enabled = enabled;
    Disconnect();
    m_outgoing = DerpSendQueue(MaximumQueuedPackets, MaximumQueuedBytes);
    m_eventLoop->DiscardPostedEvents(m_options.ReadinessToken);
    m_nextReconnect = m_timeProvider.Now();
    m_reconnectDelay = InitialReconnectDelay;
    if (enabled)
    {
        Maintain();
    }
}

void ConnectionImpl::ChangeNetwork(std::string networkInterface)
{
    m_options.NetworkInterface = std::move(networkInterface);
    Disconnect();
    m_eventLoop->DiscardPostedEvents(m_options.ReadinessToken);
    m_nextReconnect = m_timeProvider.Now();
    m_reconnectDelay = InitialReconnectDelay;
    Maintain();
}

void ConnectionImpl::Maintain()
{
    if (!m_enabled)
    {
        return;
    }
    if (m_client)
    {
        try
        {
            FlushOutgoing();
            UpdateWriteInterest();
        }
        catch (const std::exception& error)
        {
            m_logger.LogWarning(
                "connection maintenance failed host={} error={}", m_options.Host, error.what());
            ScheduleReconnect();
        }
        return;
    }
    if (m_timeProvider.Now() < m_nextReconnect)
    {
        return;
    }
    try
    {
        Connect();
    }
    catch (const std::exception& error)
    {
        m_logger.LogWarning("connection failed host={} retry-seconds={} error={}",
                            m_options.Host,
                            m_reconnectDelay.count(),
                            error.what());
        ScheduleReconnect();
    }
}

void ConnectionImpl::Send(const tailgate::derp::DerpClient::Key& destination,
                          std::vector<std::uint8_t> packet,
                          tailgate::derp::DerpSendQueue::Priority priority)
{
    if (!m_enabled)
    {
        return;
    }
    const tailgate::derp::DerpSendQueue::PushResult pushed = m_outgoing.Push(
        tailgate::derp::DerpSendQueue::Packet{
            .Destination = destination,
            .Payload = std::move(packet),
        },
        priority);
    if (!pushed.Accepted)
    {
        m_logger.LogWarning("dropping oversized queued packet host={}", m_options.Host);
        return;
    }
    if (pushed.DroppedPackets != 0)
    {
        m_logger.LogWarning(
            "queue limit reached host={} dropped={}", m_options.Host, pushed.DroppedPackets);
    }
    Maintain();
}

void ConnectionImpl::FlushOutgoing()
{
    if (!m_client)
    {
        return;
    }
    for (std::size_t frame = 0; frame < MaximumFramesPerFlush && !m_client->HasPendingOutput();
         ++frame)
    {
        std::optional<tailgate::derp::DerpSendQueue::Packet> outgoing = m_outgoing.Pop();
        if (!outgoing)
        {
            break;
        }
        m_client->Send(outgoing->Destination, outgoing->Payload);
    }
    if (m_client->HasPendingOutput())
    {
        m_client->Flush();
    }
}

std::vector<tailgate::derp::DerpClient::Packet> ConnectionImpl::DrainIncoming()
{
    return m_client ? m_client->ReceiveAvailableBatch()
                    : std::vector<tailgate::derp::DerpClient::Packet>{};
}

void ConnectionImpl::UpdateWriteInterest()
{
    if (m_socket && m_client)
    {
        if (m_client->HasBufferedInput())
        {
            m_eventLoop->Post(
                tailgate::base::Event{.Token = m_options.ReadinessToken,
                                      .Readiness = tailgate::base::EventReadiness::Readable});
        }
        m_socket->SetWriteInterest(m_socket->ReadNeedsWrite() ||
                                   (!m_socket->WriteNeedsRead() &&
                                    (m_client->HasPendingOutput() || m_outgoing.Size() != 0)));
    }
}

tailgate::derp::ConnectionEventResult
ConnectionImpl::ProcessEvent(const tailgate::base::Event& event)
{
    if (event.Token != m_options.ReadinessToken)
    {
        return {};
    }
    tailgate::derp::ConnectionEventResult result{
        .Handled = true,
        .Status = tailgate::derp::ConnectionEventStatus::Ready,
        .Packets = {},
    };
    if (!m_client)
    {
        Maintain();
        if (!m_client)
        {
            return result;
        }
    }
    if (tailgate::base::HasReadiness(event.Readiness, tailgate::base::EventReadiness::Error) ||
        tailgate::base::HasReadiness(event.Readiness, tailgate::base::EventReadiness::Closed))
    {
        ScheduleReconnect();
        result.Status = tailgate::derp::ConnectionEventStatus::Disconnected;
        return result;
    }
    try
    {
        FlushOutgoing();
        if (tailgate::base::HasReadiness(event.Readiness, tailgate::base::EventReadiness::Writable))
        {
            if (m_socket->ReadNeedsWrite())
            {
                result.Packets = DrainIncoming();
            }
            if (!m_socket->ReadNeedsWrite() && m_client->HasPendingOutput())
            {
                m_client->Flush();
            }
        }
        if (tailgate::base::HasReadiness(event.Readiness,
                                         tailgate::base::EventReadiness::Readable) ||
            m_client->HasBufferedInput())
        {
            if (m_client->HasPendingOutput() && m_socket->WriteNeedsRead())
            {
                m_client->Flush();
            }
            if (!m_socket->WriteNeedsRead())
            {
                std::vector<tailgate::derp::DerpClient::Packet> packets = DrainIncoming();
                result.Packets.insert(result.Packets.end(),
                                      std::make_move_iterator(packets.begin()),
                                      std::make_move_iterator(packets.end()));
            }
        }
        UpdateWriteInterest();
    }
    catch (const std::exception& error)
    {
        m_logger.LogWarning("connection lost host={} error={}", m_options.Host, error.what());
        ScheduleReconnect();
        result.Status = tailgate::derp::ConnectionEventStatus::Disconnected;
    }
    return result;
}

bool ConnectionImpl::Connected() const noexcept
{
    return m_client != nullptr;
}

ConnectionFactoryImpl::ConnectionFactoryImpl(
    std::shared_ptr<tailgate::types::nettype::TcpSocketFactory> socketFactory,
    tailgate::base::TimeProvider& timeProvider,
    std::shared_ptr<tailgate::base::EventLoop> eventLoop) noexcept
    : m_socketFactory(std::move(socketFactory)),
      m_timeProvider(timeProvider),
      m_eventLoop(std::move(eventLoop))
{
}

std::unique_ptr<tailgate::derp::Connection>
ConnectionFactoryImpl::CreateConnection(tailgate::derp::ConnectionOptions options)
{
    return std::make_unique<ConnectionImpl>(
        std::move(options), m_socketFactory, m_timeProvider, m_eventLoop);
}

} // namespace tailgate::derp::impl
