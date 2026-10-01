#include "tailgate/base/EventLoop.h"

namespace tailgate::base
{

EventLoop::~EventLoop() = default;

void EventLoop::Post(Event event)
{
    {
        std::lock_guard lock(m_postedMutex);
        auto& readiness = m_posted[event.Token.Value];
        readiness = readiness | event.Readiness;
    }
    Wake();
}

std::vector<Event> EventLoop::TakePostedEvents(std::size_t maximumEvents)
{
    std::vector<Event> result;
    bool remaining = false;
    {
        std::lock_guard lock(m_postedMutex);
        while (!m_posted.empty() && result.size() < maximumEvents)
        {
            const auto first = m_posted.begin();
            result.push_back(
                Event{.Token = EventToken{.Value = first->first}, .Readiness = first->second});
            m_posted.erase(first);
        }
        remaining = !m_posted.empty();
    }
    if (remaining)
    {
        Wake();
    }
    return result;
}

void EventLoop::DiscardPostedEvents(EventToken token)
{
    std::lock_guard lock(m_postedMutex);
    m_posted.erase(token.Value);
}

} // namespace tailgate::base
