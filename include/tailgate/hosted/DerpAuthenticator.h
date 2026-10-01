#pragma once

#include <condition_variable>
#include <map>
#include <mutex>

#include <tailgate/derp/Client.h>
#include <tailgate/hosted/ServerWriter.h>

namespace tailgate::hosted
{

// Correlates delegated authentication without doing stream I/O on a dial worker.
class DerpAuthenticator final : public derp::Authenticator
{
public:
    DerpAuthenticator(ServerSession& session, ServerWriter& writer);
    [[nodiscard]] std::vector<std::uint8_t> Authenticate(const derp::DerpClient::Key& serverKey,
                                                         std::stop_token cancellation) override;
    void AcceptResponse(DerpAuthenticationResponse response);

private:
    ServerSession& m_session;
    ServerWriter& m_writer;
    std::mutex m_mutex;
    std::condition_variable_any m_changed;
    std::map<std::uint64_t, std::optional<std::vector<std::uint8_t>>> m_responses;
};

} // namespace tailgate::hosted
