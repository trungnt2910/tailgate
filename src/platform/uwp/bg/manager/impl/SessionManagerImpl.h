#pragma once

#include <array>
#include <memory>
#include <mutex>

#include "manager/SessionManager.h"

namespace tailgate::uwp::bg::manager
{

class ForegroundConnectionMonitor;

class SessionManagerImpl final : public SessionManager
{
public:
    SessionManagerImpl();
    ~SessionManagerImpl() override;

    [[nodiscard]] SessionGeneration BeginConnect() override;
    void Report(const SessionEvent& event) override;
    void Notify(SessionGeneration generation,
                const ForegroundConnectionNotification& notification) override;
    void StartForegroundMonitor(const std::string& tailgateServer,
                                ForegroundCancellationHandler cancelled) override;
    void StopForegroundMonitor() override;
    void WriteState(const control::NetworkConfig& config) override;
    void SignalStateChanged() override;
    void BeginStop() override;
    void CompleteStop() override;
    void Reset() override;

    [[nodiscard]] SessionGeneration Generation() const override;
    [[nodiscard]] SessionState State() const override;

private:
    enum class ComponentState
    {
        Idle,
        Connecting,
        AuthenticationRequired,
        Ready,
        Recovering,
        Failed,
    };

    static constexpr std::size_t ComponentCount = 4;

    [[nodiscard]] static std::size_t Index(SessionComponent component);
    void UpdateAggregateState();

    mutable std::mutex m_mutex;
    std::unique_ptr<ForegroundConnectionMonitor> m_foregroundMonitor;
    SessionGeneration m_generation = 0;
    SessionState m_state = SessionState::Stopped;
    std::array<ComponentState, ComponentCount> m_components{};
};

} // namespace tailgate::uwp::bg::manager
