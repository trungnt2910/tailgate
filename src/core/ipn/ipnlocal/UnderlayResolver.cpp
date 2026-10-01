#include "tailgate/ipn/ipnlocal/UnderlayResolver.h"

#include <utility>

#include <tailgate/base/Logger.h>

namespace tailgate::ipn::ipnlocal
{

UnderlayResolver::UnderlayResolver(net::netmon::Resolver& resolver,
                                   base::EventLoop& events,
                                   base::TimeProvider& time)
    : m_resolver(resolver), m_events(events), m_time(time)
{
}

UnderlayResolver::~UnderlayResolver()
{
    Cancel();
    if (m_worker.joinable())
    {
        m_worker.join();
    }
}

void UnderlayResolver::Cancel()
{
    ++m_generation;
    m_pending.reset();
    m_deadline.reset();
    m_worker.request_stop();
}

void UnderlayResolver::Start(std::string host,
                             std::uint16_t port,
                             std::optional<std::string> networkInterface)
{
    Cancel();
    m_pending =
        Request{.Host = std::move(host), .Port = port, .Interface = std::move(networkInterface)};
    m_backoff.Reset();
    m_deadline = m_time.Now();
    m_events.Wake();
}

std::optional<net::Endpoint> UnderlayResolver::Poll()
{
    std::optional<Completion> completion;
    {
        std::lock_guard lock(m_mutex);
        completion = std::exchange(m_completed, std::nullopt);
    }
    std::optional<net::Endpoint> result;
    if (completion)
    {
        m_worker.join();
        if (completion->Generation == m_generation)
        {
            result = completion->Endpoint;
            if (result)
            {
                m_pending.reset();
                m_deadline.reset();
            }
            else
            {
                m_deadline = m_time.Now() + m_backoff.NextDelay();
            }
        }
    }
    if (m_pending && m_deadline && m_time.Now() >= *m_deadline && !m_worker.joinable())
    {
        auto request = *m_pending;
        m_deadline.reset();
        m_worker = std::jthread(
            [this, generation = m_generation, request = std::move(request)](
                std::stop_token cancellation)
            {
                Completion complete{.Generation = generation, .Endpoint = {}};
                try
                {
                    complete.Endpoint = m_resolver.Resolve(
                        request.Host, request.Port, request.Interface, cancellation);
                }
                catch (...)
                {
                    if (!cancellation.stop_requested())
                    {
                        base::Logger("underlay-dns")
                            .LogWarning("STUN lookup failed; retaining DERP fallback");
                    }
                }
                {
                    std::lock_guard lock(m_mutex);
                    m_completed = std::move(complete);
                }
                m_events.Wake();
            });
    }
    return result;
}

} // namespace tailgate::ipn::ipnlocal
