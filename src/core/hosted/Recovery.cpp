#include "tailgate/hosted/Recovery.h"

#include <utility>

#include <tailgate/base/Logger.h>
#include <tailgate/hosted/RelayEndpoint.h>

namespace tailgate::hosted
{

Recovery::Recovery(types::nettype::TcpSocketFactory& sockets,
                   base::EventLoop& events,
                   base::TimeProvider& time)
    : m_sockets(sockets), m_events(events), m_time(time)
{
}

Recovery::~Recovery()
{
    Reset();
}

void Recovery::Reset()
{
    Cancel();
    // Dependencies outlive this owner; cancellation interrupts bootstrap I/O.
    if (m_worker.joinable())
    {
        m_worker.join();
    }
    m_completion.reset();
    m_options.reset();
    m_backoff.Reset();
}

void Recovery::Configure(ConnectionOptions options)
{
    Cancel();
    m_options = std::move(options);
    m_backoff.Reset();
}

void Recovery::Cancel()
{
    ++m_generation;
    m_worker.request_stop();
    m_deadline.reset();
    std::lock_guard lock(m_mutex);
    if (m_completion)
    {
        m_completion->Connection.reset();
    }
}

void Recovery::Failed()
{
    if (m_options && !m_deadline)
    {
        m_deadline = m_time.Now() + m_backoff.NextDelay();
    }
}

void Recovery::ChangeNetwork(std::string networkInterface)
{
    if (!m_options)
    {
        return;
    }
    Cancel();
    m_options->Socket.NetworkInterface = std::move(networkInterface);
    m_deadline = m_time.Now();
    m_events.Wake();
}

std::optional<ConnectionResult> Recovery::Poll()
{
    std::optional<Completion> completed;
    {
        std::lock_guard lock(m_mutex);
        completed = std::exchange(m_completion, std::nullopt);
    }
    if (completed)
    {
        m_worker.join();
        if (completed->Generation == m_generation)
        {
            if (completed->Connection)
            {
                m_backoff.Reset();
                m_deadline.reset();
                return std::move(completed->Connection);
            }
            base::Logger("hosted-recovery").LogWarning("relay bootstrap failed; retry scheduled");
            m_deadline.reset();
            Failed();
        }
    }
    if (!m_options || !m_deadline || m_worker.joinable() || m_time.Now() < *m_deadline)
    {
        return std::nullopt;
    }
    const auto generation = m_generation;
    auto options = *m_options;
    m_deadline.reset();
    m_worker = std::jthread(
        [this, generation, options = std::move(options)](std::stop_token cancellation) mutable
        {
            Completion completion{.Generation = generation, .Connection = {}, .Error = {}};
            try
            {
                auto endpoint = RelayEndpoint{
                    .Host = options.Socket.TlsServerName.value_or(options.Socket.ConnectAddress),
                    .ConnectAddress = {},
                    .Port = options.Socket.Service};
                endpoint.Resolve(m_sockets,
                                 options.Socket.NetworkInterface,
                                 0,
                                 cancellation,
                                 options.Socket.AllowTls13);
                options.Socket.ConnectAddress = endpoint.ConnectAddress;
                options.Socket.TlsServerName = endpoint.Host;
                options.Socket.Cancellation = cancellation;
                completion.Connection = Connection(m_sockets).Connect(std::move(options));
            }
            catch (...)
            {
                completion.Error = std::current_exception();
            }
            {
                std::lock_guard lock(m_mutex);
                if (cancellation.stop_requested())
                {
                    completion.Connection.reset();
                }
                m_completion = std::move(completion);
            }
            m_events.Wake();
        });
    return std::nullopt;
}

std::optional<base::TimeProvider::TimePoint> Recovery::Deadline() const noexcept
{
    // An in-flight worker wakes the event loop itself. Do not spin on an expired deadline.
    return m_worker.joinable() ? std::nullopt : m_deadline;
}

} // namespace tailgate::hosted
