#pragma once

#include <mutex>
#include <thread>

#include <tailgate/base/EventLoop.h>
#include <tailgate/control/client/RetryBackoff.h>
#include <tailgate/net/netmon/Resolver.h>

namespace tailgate::ipn::ipnlocal
{

// DNS runs outside the serialized packet owner. Completions are tied to a network generation.
class UnderlayResolver final
{
public:
    UnderlayResolver(net::netmon::Resolver& resolver,
                     base::EventLoop& events,
                     base::TimeProvider& time);
    ~UnderlayResolver();
    void Start(std::string host, std::uint16_t port, std::optional<std::string> networkInterface);
    void Cancel();
    [[nodiscard]] std::optional<net::Endpoint> Poll();

private:
    struct Request
    {
        std::string Host;
        std::uint16_t Port = 0;
        std::optional<std::string> Interface;
    };

    struct Completion
    {
        std::uint64_t Generation = 0;
        std::optional<net::Endpoint> Endpoint;
    };

    net::netmon::Resolver& m_resolver;
    base::EventLoop& m_events;
    base::TimeProvider& m_time;
    control::client::RetryBackoff m_backoff{std::chrono::seconds(1), std::chrono::seconds(30)};
    std::optional<base::TimeProvider::TimePoint> m_deadline;
    std::optional<Request> m_pending;
    std::uint64_t m_generation = 0;
    std::mutex m_mutex;
    std::optional<Completion> m_completed;
    std::jthread m_worker;
};

} // namespace tailgate::ipn::ipnlocal
