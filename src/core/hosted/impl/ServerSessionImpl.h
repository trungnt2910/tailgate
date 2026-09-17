#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include <tailgate/hosted/Pump.h>
#include <tailgate/hosted/ServerSession.h>

namespace tailgate::hosted::impl
{

class ServerSessionImpl final : public tailgate::hosted::ServerSession
{
public:
    ServerSessionImpl(tailgate::hosted::ServerSessionOptions options,
                      tailgate::base::TimeProvider& timeProvider);

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
    [[nodiscard]] std::optional<tailgate::base::TimeProvider::TimePoint>
    NextPumpDeadline() const override;
    [[nodiscard]] std::optional<tailgate::hosted::Frame> TakeDuePump() override;
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
    [[nodiscard]] bool AcceptPump(const tailgate::hosted::PumpSchedule& schedule);
    [[nodiscard]] bool
    ValidateNetworkMap(const tailgate::types::netmap::NetworkConfig& candidate) const;

    mutable std::mutex m_mutex;
    tailgate::base::TimeProvider& m_timeProvider;
    std::optional<tailgate::base::TimeProvider::TimePoint> m_pumpDeadline;
    std::optional<tailgate::base::TimeProvider::TimePoint> m_lastPump;
    std::uint64_t m_pumpRequestId = 0;
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
    explicit ServerSessionFactoryImpl(tailgate::base::TimeProvider& timeProvider) noexcept;
    [[nodiscard]] std::unique_ptr<tailgate::hosted::ServerSession>
    CreateServerSession(tailgate::hosted::ServerSessionOptions options) override;

private:
    tailgate::base::TimeProvider& m_timeProvider;
};

} // namespace tailgate::hosted::impl
