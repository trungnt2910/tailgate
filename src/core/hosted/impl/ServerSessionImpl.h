#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include <tailgate/hosted/ServerSession.h>

namespace tailgate::hosted::impl
{

class ServerSessionImpl final : public tailgate::hosted::ServerSession
{
public:
    explicit ServerSessionImpl(tailgate::hosted::ServerSessionOptions options);

    [[nodiscard]] tailgate::hosted::Frame StartAuthentication() override;
    [[nodiscard]] tailgate::hosted::ServerAuthenticationResult
    EvaluateAuthentication(const tailgate::hosted::Frame& frame) override;
    [[nodiscard]] tailgate::hosted::Frame CompleteAuthentication(bool nodeVisible) override;
    [[nodiscard]] tailgate::types::netmap::NetworkConfig
    AcceptInitialNetworkMap(const tailgate::hosted::Frame& frame) override;
    [[nodiscard]] tailgate::hosted::ServerSessionProcessResult
    Process(const tailgate::hosted::Frame& frame) override;
    [[nodiscard]] tailgate::hosted::ServerDerpChallenge
    BuildDerpChallenge(const tailgate::crypto::Bytes32& serverKey) override;
    [[nodiscard]] tailgate::hosted::Frame BuildHeartbeat() const override;
    [[nodiscard]] tailgate::hosted::Frame
    BuildServerPacket(std::vector<std::uint8_t> peerPacketPayload) const override;

private:
    enum class State
    {
        Created,
        ChallengeSent,
        AuthenticationEvaluated,
        Authenticated,
        Active,
        Rejected,
    };

    void RequireState(State expected) const;
    void RequireActive() const;
    [[nodiscard]] bool
    ValidateNetworkMap(const tailgate::types::netmap::NetworkConfig& candidate) const;

    mutable std::mutex m_mutex;
    tailgate::hosted::ServerSessionOptions m_options;
    tailgate::crypto::Bytes32 m_serverNonce{};
    std::optional<tailgate::hosted::Authentication> m_authentication;
    tailgate::types::netmap::NetworkConfig m_networkMap;
    std::uint64_t m_nextDerpRequestId = 1;
    State m_state = State::Created;
    bool m_proofValid = false;
    bool m_tailnetMatches = false;
};

class ServerSessionFactoryImpl final : public tailgate::hosted::ServerSessionFactory
{
public:
    [[nodiscard]] std::unique_ptr<tailgate::hosted::ServerSession>
    CreateServerSession(tailgate::hosted::ServerSessionOptions options) override;
};

} // namespace tailgate::hosted::impl
