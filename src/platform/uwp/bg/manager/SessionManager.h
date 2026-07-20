#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include <tailgate/control/NetworkMap.h>

namespace tailgate::uwp::bg::manager
{

using SessionGeneration = std::uint64_t;

enum class ForegroundConnectionKind
{
    LoginRequired,
    MachineApprovalRequired,
    ControlAuthorized,
    Failed,
};

struct ForegroundConnectionNotification
{
    ForegroundConnectionKind Kind = ForegroundConnectionKind::LoginRequired;
    std::string Url;
    std::string TailgateServer;
    std::uint32_t ErrorCode = 0;
};

enum class ForegroundCancellationReason
{
    Cancelled,
    ForegroundExited,
};

using ForegroundCancellationHandler = std::function<void(ForegroundCancellationReason)>;

enum class SessionState
{
    Stopped,
    Starting,
    AwaitingAuthentication,
    Running,
    Reconnecting,
    Stopping,
    Failed,
};

enum class SessionComponent
{
    Probe,
    ControlPlane,
    DataPlane,
    Platform,
};

enum class SessionEventKind
{
    Connecting,
    AuthenticationRequired,
    Ready,
    Recovering,
    TerminalFailure,
};

struct SessionEvent
{
    SessionGeneration Generation = 0;
    SessionComponent Component = SessionComponent::Probe;
    SessionEventKind Kind = SessionEventKind::Connecting;
};

class SessionManager
{
public:
    virtual ~SessionManager() = default;

    [[nodiscard]] virtual SessionGeneration BeginConnect() = 0;
    virtual void Report(const SessionEvent& event) = 0;
    virtual void Notify(SessionGeneration generation,
                        const ForegroundConnectionNotification& notification) = 0;
    virtual void StartForegroundMonitor(const std::string& tailgateServer,
                                        ForegroundCancellationHandler cancelled) = 0;
    virtual void StopForegroundMonitor() = 0;
    virtual void WriteState(const control::NetworkConfig& config) = 0;
    virtual void SignalStateChanged() = 0;
    virtual void BeginStop() = 0;
    virtual void CompleteStop() = 0;
    virtual void Reset() = 0;

    [[nodiscard]] virtual SessionGeneration Generation() const = 0;
    [[nodiscard]] virtual SessionState State() const = 0;
};

} // namespace tailgate::uwp::bg::manager
