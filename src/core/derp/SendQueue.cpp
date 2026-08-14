#include <tailgate/derp/SendQueue.h>

#include <stdexcept>
#include <utility>

namespace tailgate::derp
{

DerpSendQueue::DerpSendQueue(std::size_t maximumPackets, std::size_t maximumBytes)
    : m_maximumPackets(maximumPackets), m_maximumBytes(maximumBytes)
{
    if (maximumPackets == 0 || maximumBytes == 0)
    {
        throw std::invalid_argument("DERP queue limits must be positive.");
    }
}

DerpSendQueue::PushResult DerpSendQueue::Push(Packet packet, Priority priority)
{
    PushResult result;
    if (packet.Payload.size() > m_maximumBytes)
    {
        return result;
    }
    while (Size() > 0 &&
           (Size() >= m_maximumPackets || m_bytes + packet.Payload.size() > m_maximumBytes))
    {
        std::deque<Packet>& queue = m_data.empty() ? m_control : m_data;
        m_bytes -= queue.front().Payload.size();
        queue.pop_front();
        ++result.DroppedPackets;
    }
    m_bytes += packet.Payload.size();
    if (priority == Priority::Control)
    {
        m_control.push_back(std::move(packet));
    }
    else
    {
        m_data.push_back(std::move(packet));
    }
    result.Accepted = true;
    return result;
}

std::optional<DerpSendQueue::Packet> DerpSendQueue::Pop()
{
    std::deque<Packet>& queue = m_control.empty() ? m_data : m_control;
    if (queue.empty())
    {
        return std::nullopt;
    }
    Packet packet = std::move(queue.front());
    queue.pop_front();
    m_bytes -= packet.Payload.size();
    return packet;
}

std::size_t DerpSendQueue::Size() const
{
    return m_control.size() + m_data.size();
}

std::size_t DerpSendQueue::Bytes() const
{
    return m_bytes;
}

} // namespace tailgate::derp
