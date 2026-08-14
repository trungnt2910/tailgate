#pragma once

#include <cstdint>
#include <vector>

#include <winrt/base.h>

#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"

#include "common/MappedView.h"
#include "common/UwpError.h"

namespace tailgate::uwp
{

enum class ConnectionMessageKind : std::uint32_t
{
    LoginRequired = 1,
    MachineApprovalRequired = 2,
    ControlAuthorized = 3,
    Failed = 4,
};

enum class ConnectionCancellationReason
{
    Cancelled,
    ForegroundExited,
    MonitorStopped,
    Unavailable,
};

struct ConnectionMessage
{
    ConnectionMessageKind Kind = ConnectionMessageKind::LoginRequired;
    winrt::hstring Url;
    winrt::hstring TailgateServer;
    UwpError::Code ErrorCode = UwpError::Code::None;
};

class AuthorizationStateReceiver final
{
public:
    explicit AuthorizationStateReceiver(const winrt::hstring& expectedTailgateServer);
    ~AuthorizationStateReceiver();

    AuthorizationStateReceiver(const AuthorizationStateReceiver&) = delete;
    AuthorizationStateReceiver& operator=(const AuthorizationStateReceiver&) = delete;
    AuthorizationStateReceiver(AuthorizationStateReceiver&&) = delete;
    AuthorizationStateReceiver& operator=(AuthorizationStateReceiver&&) = delete;

    [[nodiscard]] std::vector<ConnectionMessage> ReadAvailable();
    [[nodiscard]] void* WaitHandle() const;
    void Signal();
    void Cancel();

private:
    winrt::handle m_mapping;
    MappedView m_view;
    winrt::handle m_event;
    winrt::handle m_cancelEvent;
    long m_nextSequence = 0;
    tailgate::base::Logger m_logger{"uwp-auth-receiver"};
};

class ConnectionCancellationMonitor final
{
public:
    explicit ConnectionCancellationMonitor(const winrt::hstring& expectedTailgateServer);
    ~ConnectionCancellationMonitor();

    ConnectionCancellationMonitor(const ConnectionCancellationMonitor&) = delete;
    ConnectionCancellationMonitor& operator=(const ConnectionCancellationMonitor&) = delete;
    ConnectionCancellationMonitor(ConnectionCancellationMonitor&&) = delete;
    ConnectionCancellationMonitor& operator=(ConnectionCancellationMonitor&&) = delete;

    [[nodiscard]] bool Available() const noexcept;
    [[nodiscard]] ConnectionCancellationReason Wait(void* stopHandle) const;

private:
    winrt::handle m_mapping;
    MappedView m_view;
    winrt::handle m_cancelEvent;
    winrt::handle m_foregroundProcess;
    tailgate::base::Logger m_logger{"uwp-connection-cancel"};
};

[[nodiscard]] bool PublishConnectionMessage(const ConnectionMessage& message);

} // namespace tailgate::uwp
