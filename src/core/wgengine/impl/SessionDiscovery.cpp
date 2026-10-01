#include "SessionImpl.h"

#include <algorithm>
#include <system_error>

#include <tailgate/base/Logger.h>

namespace tailgate::wgengine::impl
{

void SessionImpl::StartEndpointDiscovery(const net::Endpoint& server,
                                         std::chrono::milliseconds timeout)
{
    const auto now = m_timeProvider.Now();
    m_discovery = Discovery{.Transaction = net::stun::TransactionId::Generate(m_random),
                            .Server = server,
                            .Deadline = now + timeout,
                            .NextSend = now,
                            .RetryDelay = InitialStunRetryDelay};
}

void SessionImpl::CancelEndpointDiscovery() noexcept
{
    m_discovery.reset();
}

void SessionImpl::PollEndpointDiscovery(SessionWaitResult& result)
{
    if (!m_discovery)
    {
        return;
    }
    const auto now = m_timeProvider.Now();
    if (now >= m_discovery->Deadline)
    {
        result.EndpointDiscovery = EndpointDiscoveryResult{};
        CancelEndpointDiscovery();
        return;
    }
    if (now >= m_discovery->NextSend)
    {
        std::optional<types::nettype::SocketIoResult> sent;
        try
        {
            sent = m_connection.TrySendProbe(m_discovery->Server,
                                             m_discovery->Transaction.BuildBindingRequest());
        }
        catch (const std::system_error& error)
        {
            base::Logger("endpoint-discovery")
                .LogWarning("STUN send failed: {}", error.code().value());
        }
        if (!sent || *sent == types::nettype::SocketIoResult::Closed)
        {
            result.EndpointDiscovery = EndpointDiscoveryResult{};
            CancelEndpointDiscovery();
            return;
        }
        // A dropped or backpressured request is retried on a timer, without holding
        // up packet dispatch. Retransmissions keep the original transaction ID.
        const auto remaining = m_discovery->Deadline - now;
        const auto delay =
            std::min<base::TimeProvider::Duration>(m_discovery->RetryDelay, remaining);
        m_discovery->NextSend = now + delay;
        m_discovery->RetryDelay += m_discovery->RetryDelay;
    }
}

bool SessionImpl::ProcessEndpointResponse(const types::nettype::UdpDatagram& datagram,
                                          SessionWaitResult& result)
{
    if (!m_discovery || datagram.Source != m_discovery->Server ||
        m_timeProvider.Now() >= m_discovery->Deadline)
    {
        return false;
    }
    const auto endpoint = m_discovery->Transaction.ParseMappedIpv4Endpoint(datagram.Payload);
    if (!endpoint || endpoint->Port() == 0 || endpoint->Address().HostOrder() == 0)
    {
        return false;
    }
    result.EndpointDiscovery = EndpointDiscoveryResult{.Endpoint = endpoint};
    CancelEndpointDiscovery();
    return true;
}

} // namespace tailgate::wgengine::impl
