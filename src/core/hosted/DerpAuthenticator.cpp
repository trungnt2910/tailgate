#include "tailgate/hosted/DerpAuthenticator.h"

#include <chrono>
#include <system_error>
#include <utility>

namespace tailgate::hosted
{

DerpAuthenticator::DerpAuthenticator(ServerSession& session, ServerWriter& writer)
    : m_session(session), m_writer(writer)
{
}

std::vector<std::uint8_t> DerpAuthenticator::Authenticate(const derp::DerpClient::Key& serverKey,
                                                          std::stop_token cancellation)
{
    if (cancellation.stop_requested())
    {
        throw std::system_error(std::make_error_code(std::errc::operation_canceled));
    }
    const auto challenge = m_session.BuildDerpChallenge(serverKey);
    std::unique_lock lock(m_mutex);
    m_responses.emplace(challenge.RequestId, std::nullopt);
    try
    {
        m_writer.Post(challenge.Output);
        constexpr std::chrono::seconds AuthenticationTimeout{30};
        const bool ready =
            m_changed.wait_for(lock,
                               cancellation,
                               AuthenticationTimeout,
                               [&]()
                               {
                                   return m_responses.at(challenge.RequestId).has_value();
                               });
        if (!ready || cancellation.stop_requested())
        {
            throw std::system_error(std::make_error_code(cancellation.stop_requested()
                                                             ? std::errc::operation_canceled
                                                             : std::errc::timed_out));
        }
        auto response = std::move(*m_responses.at(challenge.RequestId));
        m_responses.erase(challenge.RequestId);
        return response;
    }
    catch (...)
    {
        m_responses.erase(challenge.RequestId);
        throw;
    }
}

void DerpAuthenticator::AcceptResponse(DerpAuthenticationResponse response)
{
    {
        std::lock_guard lock(m_mutex);
        auto found = m_responses.find(response.RequestId());
        if (found == m_responses.end() || found->second)
        {
            // Cancellation may race a valid response already in transit.
            return;
        }
        found->second = std::move(response.ClientInfo());
    }
    m_changed.notify_all();
}

} // namespace tailgate::hosted
