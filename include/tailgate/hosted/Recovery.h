#pragma once

#include <exception>
#include <mutex>
#include <thread>

#include <tailgate/base/EventLoop.h>
#include <tailgate/control/client/RetryBackoff.h>
#include <tailgate/hosted/Connection.h>

namespace tailgate::hosted
{

// Serialized scheduling around a cancellable bootstrap worker. The worker owns only
// candidate sockets; it never accesses the node's WireGuard or local-service state.
class Recovery final
{
public:
    Recovery(types::nettype::TcpSocketFactory& sockets,
             base::EventLoop& events,
             base::TimeProvider& time);
    ~Recovery();
    void Configure(ConnectionOptions options);
    void Failed();
    void ChangeNetwork(std::string networkInterface);
    void Cancel();
    // Stop and join bootstrap work before retiring a session.
    void Reset();
    [[nodiscard]] std::optional<ConnectionResult> Poll();
    [[nodiscard]] std::optional<base::TimeProvider::TimePoint> Deadline() const noexcept;

private:
    struct Completion
    {
        std::uint64_t Generation = 0;
        std::optional<ConnectionResult> Connection;
        std::exception_ptr Error;
    };

    types::nettype::TcpSocketFactory& m_sockets;
    base::EventLoop& m_events;
    base::TimeProvider& m_time;
    std::optional<ConnectionOptions> m_options;
    std::optional<base::TimeProvider::TimePoint> m_deadline;
    control::client::RetryBackoff m_backoff{std::chrono::seconds(1), std::chrono::seconds(30)};
    std::uint64_t m_generation = 0;
    std::mutex m_mutex;
    std::optional<Completion> m_completion;
    std::jthread m_worker;
};

} // namespace tailgate::hosted
