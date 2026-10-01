#include "tailgate/ipn/ipnlocal/UnderlaySelection.h"

#include <algorithm>
#include <utility>

namespace tailgate::ipn::ipnlocal
{

UnderlaySelection::UnderlaySelection(base::TimeProvider& time) : m_time(time)
{
}

void UnderlaySelection::Start(net::netmon::Snapshot snapshot,
                              const std::optional<std::string>& selected)
{
    m_snapshot = std::move(snapshot);
    const auto found =
        std::ranges::find(m_snapshot.Networks, selected, &net::netmon::Network::Interface);
    m_selected = found == m_snapshot.Networks.end()
                     ? 0
                     : static_cast<std::size_t>(found - m_snapshot.Networks.begin());
    ++m_generation;
    m_deadline = m_time.Now() + ReachabilityTimeout;
}

std::optional<UnderlayChange> UnderlaySelection::Poll(net::netmon::Snapshot snapshot, bool ready)
{
    const auto now = m_time.Now();
    const bool changed = snapshot.Networks != m_snapshot.Networks;
    if (changed)
    {
        auto previous = m_snapshot.Networks.empty() ? std::optional<net::netmon::Network>{}
                                                    : m_snapshot.Networks[m_selected];
        m_snapshot = std::move(snapshot);
        m_selected = 0;
        if (previous)
        {
            const auto existing = std::ranges::find(m_snapshot.Networks, *previous);
            if (existing != m_snapshot.Networks.end())
            {
                m_selected = static_cast<std::size_t>(existing - m_snapshot.Networks.begin());
                // An unrelated adapter appearing does not invalidate a working socket.
                if (ready)
                {
                    return std::nullopt;
                }
            }
        }
    }
    else
    {
        if (ready)
        {
            m_deadline = now + ReachabilityTimeout;
            return std::nullopt;
        }
        if (now < m_deadline || m_snapshot.Networks.empty())
        {
            return std::nullopt;
        }
        m_selected = (m_selected + 1) % m_snapshot.Networks.size();
    }
    m_deadline = now + ReachabilityTimeout;
    return UnderlayChange{.Generation = ++m_generation,
                          .Network = m_snapshot.Networks.empty()
                                         ? std::optional<net::netmon::Network>{}
                                         : m_snapshot.Networks[m_selected]};
}

} // namespace tailgate::ipn::ipnlocal
