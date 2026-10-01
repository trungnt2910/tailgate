#include "tailgate/wgengine/magicsock/Bind.h"

#include <map>
#include <stdexcept>
#include <system_error>

namespace tailgate::wgengine::magicsock
{
namespace
{

constexpr std::size_t MaximumBindEvents = 64;

class DeferredReadiness final
{
public:
    explicit DeferredReadiness(base::EventLoop& events) : m_events(events)
    {
    }

    ~DeferredReadiness()
    {
        for (const auto& [token, readiness] : m_deferred)
        {
            m_events.Post({.Token = {.Value = token}, .Readiness = readiness});
        }
    }

    void Add(const base::Event& event)
    {
        auto& readiness = m_deferred[event.Token.Value];
        readiness = readiness | event.Readiness;
    }

private:
    base::EventLoop& m_events;
    std::map<std::uint64_t, base::EventReadiness> m_deferred;
};

} // namespace

net::Endpoint Bind(Connection& connection,
                   const types::nettype::UdpSocketOptions& options,
                   base::EventLoop& events,
                   base::TimeProvider& time,
                   std::chrono::milliseconds timeout,
                   std::stop_token cancellation)
{
    if (options.ReadinessToken.Value == 0 || timeout <= std::chrono::milliseconds::zero())
    {
        throw std::invalid_argument("UDP binding requires a readiness token and positive timeout");
    }
    if (cancellation.stop_requested())
    {
        throw std::system_error(std::make_error_code(std::errc::operation_canceled));
    }
    if (!connection.Open(options))
    {
        throw std::system_error(std::make_error_code(std::errc::address_not_available));
    }
    DeferredReadiness deferred(events);
    try
    {
        const auto deadlineAt = time.Now() + timeout;
        const auto deadline = time.At(deadlineAt);
        std::stop_callback onStop(cancellation,
                                  [&events]()
                                  {
                                      events.Wake();
                                  });
        for (;;)
        {
            if (cancellation.stop_requested())
            {
                throw std::system_error(std::make_error_code(std::errc::operation_canceled));
            }
            if (const auto endpoint = connection.LocalEndpoint(); endpoint && endpoint->Port() != 0)
            {
                return *endpoint;
            }
            if (time.Now() >= deadlineAt)
            {
                throw std::system_error(std::make_error_code(std::errc::timed_out));
            }
            auto ready = events.Wait(*deadline, MaximumBindEvents);
            const auto completions = events.TakePostedEvents(MaximumBindEvents);
            ready.Events.insert(ready.Events.end(), completions.begin(), completions.end());
            bool failed = false;
            bool closed = false;
            for (const auto& event : ready.Events)
            {
                if (event.Token != options.ReadinessToken)
                {
                    deferred.Add(event);
                    continue;
                }
                failed |= base::HasReadiness(event.Readiness, base::EventReadiness::Error);
                closed |= base::HasReadiness(event.Readiness, base::EventReadiness::Closed);
                // Binding must not consume incoming datagrams. Preserve their readiness
                // for the packet dispatcher, including a receive racing bind completion.
                if (base::HasReadiness(event.Readiness, base::EventReadiness::Readable))
                {
                    deferred.Add(
                        {.Token = event.Token, .Readiness = base::EventReadiness::Readable});
                }
            }
            if (failed || closed)
            {
                throw std::system_error(std::make_error_code(failed ? std::errc::network_unreachable
                                                                    : std::errc::not_connected));
            }
            if (ready.Status == base::EventWaitStatus::DeadlineReached)
            {
                throw std::system_error(std::make_error_code(std::errc::timed_out));
            }
        }
    }
    catch (...)
    {
        connection.Close();
        throw;
    }
}

} // namespace tailgate::wgengine::magicsock
