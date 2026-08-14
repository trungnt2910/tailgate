#include "AuthorizationState.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <tailgate/base/Logger.h>

namespace tailgate::uwp
{

namespace
{

constexpr wchar_t AuthorizationMappingName[] = L"Tailgate.AuthorizationState";
constexpr wchar_t AuthorizationEventName[] = L"Tailgate.AuthorizationStateChanged";
constexpr wchar_t AuthorizationCancelEventName[] = L"Tailgate.AuthorizationCancelled";
constexpr std::uint32_t AuthorizationMappingMagic = 0x54474155; // 'TGAU'.
constexpr std::uint32_t AuthorizationMappingVersion = 4;
constexpr std::size_t AuthorizationQueueCapacity = 8;
constexpr std::size_t AuthorizationUrlCapacity = 4096;
constexpr std::size_t TailgateServerCapacity = 512;
tailgate::base::Logger AuthorizationPublisherLogger{"uwp-auth-publisher"};

// These fixed-capacity fields are part of the versioned cross-process shared-memory layout;
// dynamic strings cannot be stored in this mapping.
struct AuthorizationMessageSlot
{
    volatile LONG Sequence;
    std::uint32_t Kind;
    std::uint32_t UrlLength;
    std::uint32_t ErrorCode;
    std::array<char, AuthorizationUrlCapacity> Url;
};

struct AuthorizationMapping
{
    std::uint32_t Magic;
    std::uint32_t Version;
    volatile LONG WriteSequence;
    volatile LONG CancelRequested;
    std::uint32_t ForegroundProcessId;
    std::uint32_t TailgateServerLength;
    std::array<char, TailgateServerCapacity> TailgateServer;
    std::array<AuthorizationMessageSlot, AuthorizationQueueCapacity> Messages;
};

static_assert(offsetof(AuthorizationMapping, WriteSequence) % alignof(LONG) == 0);
static_assert(offsetof(AuthorizationMapping, CancelRequested) % alignof(LONG) == 0);
static_assert(offsetof(AuthorizationMessageSlot, Sequence) % alignof(LONG) == 0);

void LogHandleFailure(const tailgate::base::Logger& logger,
                      tailgate::base::LogLevel level,
                      const char* operation,
                      DWORD error)
{
    logger.Log(level, "{} failed error={}", operation, error);
}

[[noreturn]] void
ThrowHandleFailure(const tailgate::base::Logger& logger, const char* operation, DWORD error)
{
    const DWORD normalizedError = error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error;
    LogHandleFailure(logger, tailgate::base::LogLevel::Error, operation, normalizedError);
    winrt::throw_hresult(HRESULT_FROM_WIN32(normalizedError));
}

bool IsMessageKindValid(std::uint32_t value)
{
    return value >= static_cast<std::uint32_t>(ConnectionMessageKind::LoginRequired) &&
           value <= static_cast<std::uint32_t>(ConnectionMessageKind::Failed);
}

bool IsMessageContentValid(ConnectionMessageKind kind,
                           std::size_t urlLength,
                           UwpError::Code errorCode)
{
    const bool authorization = kind == ConnectionMessageKind::LoginRequired ||
                               kind == ConnectionMessageKind::MachineApprovalRequired;
    return authorization ? urlLength != 0 && errorCode == UwpError::Code::None
           : kind == ConnectionMessageKind::Failed
               ? urlLength == 0 && UwpError::IsValid(errorCode)
               : urlLength == 0 && errorCode == UwpError::Code::None;
}

} // namespace

AuthorizationStateReceiver::AuthorizationStateReceiver(const winrt::hstring& expectedTailgateServer)
{
    const std::string expectedServer = winrt::to_string(expectedTailgateServer);
    if (expectedServer.empty() || expectedServer.size() > TailgateServerCapacity)
    {
        m_logger.LogError("foreground server exceeds the authorization mapping format");
        winrt::throw_hresult(E_INVALIDARG);
    }
    SetLastError(ERROR_SUCCESS);
    winrt::handle mapping(CreateFileMappingFromApp(INVALID_HANDLE_VALUE,
                                                   nullptr,
                                                   PAGE_READWRITE,
                                                   sizeof(AuthorizationMapping),
                                                   AuthorizationMappingName));
    if (!mapping)
    {
        ThrowHandleFailure(m_logger, "CreateFileMappingFromApp", GetLastError());
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        ThrowHandleFailure(m_logger, "CreateFileMappingFromApp", ERROR_ALREADY_EXISTS);
    }
    MappedView mappedView(
        MapViewOfFileFromApp(mapping.get(), FILE_MAP_ALL_ACCESS, 0, sizeof(AuthorizationMapping)));
    if (!mappedView)
    {
        ThrowHandleFailure(m_logger, "MapViewOfFileFromApp", GetLastError());
    }
    auto* view = static_cast<AuthorizationMapping*>(mappedView.get());
    SetLastError(ERROR_SUCCESS);
    winrt::handle event(
        CreateEventExW(nullptr, AuthorizationEventName, 0, SYNCHRONIZE | EVENT_MODIFY_STATE));
    if (!event)
    {
        ThrowHandleFailure(m_logger, "CreateEventExW", GetLastError());
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        ThrowHandleFailure(m_logger, "CreateEventExW", ERROR_ALREADY_EXISTS);
    }
    SetLastError(ERROR_SUCCESS);
    winrt::handle cancelEvent(CreateEventExW(nullptr,
                                             AuthorizationCancelEventName,
                                             CREATE_EVENT_MANUAL_RESET,
                                             SYNCHRONIZE | EVENT_MODIFY_STATE));
    if (!cancelEvent)
    {
        ThrowHandleFailure(m_logger, "CreateEventExW(cancel)", GetLastError());
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        ThrowHandleFailure(m_logger, "CreateEventExW(cancel)", ERROR_ALREADY_EXISTS);
    }
    std::memset(view, 0, sizeof(*view));
    view->Magic = AuthorizationMappingMagic;
    view->Version = AuthorizationMappingVersion;
    view->ForegroundProcessId = GetCurrentProcessId();
    view->TailgateServerLength = static_cast<std::uint32_t>(expectedServer.size());
    std::memcpy(view->TailgateServer.data(), expectedServer.data(), expectedServer.size());
    InterlockedExchange(&view->WriteSequence, 0);
    m_mapping = std::move(mapping);
    m_view = std::move(mappedView);
    m_event = std::move(event);
    m_cancelEvent = std::move(cancelEvent);
    m_logger.LogDebug("foreground event queue ready");
}

AuthorizationStateReceiver::~AuthorizationStateReceiver() = default;

std::vector<ConnectionMessage> AuthorizationStateReceiver::ReadAvailable()
{
    std::vector<ConnectionMessage> result;
    if (!m_view)
    {
        return result;
    }
    auto* view = static_cast<AuthorizationMapping*>(m_view.get());
    const bool validMapping = view->Magic == AuthorizationMappingMagic &&
                              view->Version == AuthorizationMappingVersion &&
                              view->TailgateServerLength != 0 &&
                              view->TailgateServerLength <= view->TailgateServer.size();
    if (!validMapping)
    {
        m_logger.LogWarning("foreground rejected an invalid connection-attempt queue");
        return result;
    }
    const LONG published = InterlockedCompareExchange(&view->WriteSequence, 0, 0);
    LONG firstSequence = m_nextSequence + 1;
    if (published - m_nextSequence > static_cast<LONG>(AuthorizationQueueCapacity))
    {
        firstSequence = published - static_cast<LONG>(AuthorizationQueueCapacity) + 1;
        m_logger.LogWarning("foreground skipped overwritten connection-attempt messages");
    }
    const std::string expectedServer(view->TailgateServer.data(), view->TailgateServerLength);
    for (LONG sequence = firstSequence; sequence <= published; ++sequence)
    {
        const std::size_t index =
            (static_cast<std::uint32_t>(sequence) - 1U) % AuthorizationQueueCapacity;
        const AuthorizationMessageSlot& slot = view->Messages[index];
        if (InterlockedCompareExchange(const_cast<volatile LONG*>(&slot.Sequence), 0, 0) !=
            sequence)
        {
            continue;
        }
        MemoryBarrier();
        const std::uint32_t kindValue = slot.Kind;
        const std::uint32_t urlLength = slot.UrlLength;
        const auto errorCode = static_cast<UwpError::Code>(slot.ErrorCode);
        const bool valid = IsMessageKindValid(kindValue) && urlLength <= slot.Url.size() &&
                           IsMessageContentValid(
                               static_cast<ConnectionMessageKind>(kindValue), urlLength, errorCode);
        if (!valid)
        {
            m_logger.LogWarning("foreground rejected an invalid connection-attempt message");
            continue;
        }
        const std::string url(slot.Url.data(), urlLength);
        MemoryBarrier();
        if (InterlockedCompareExchange(const_cast<volatile LONG*>(&slot.Sequence), 0, 0) !=
            sequence)
        {
            continue;
        }
        ConnectionMessage message;
        message.Kind = static_cast<ConnectionMessageKind>(kindValue);
        message.Url = winrt::to_hstring(url);
        message.TailgateServer = winrt::to_hstring(expectedServer);
        message.ErrorCode = errorCode;
        result.push_back(std::move(message));
    }
    m_nextSequence = published;
    if (!result.empty())
    {
        m_logger.LogDebug("foreground drained connection-attempt messages count={}", result.size());
    }
    return result;
}

void* AuthorizationStateReceiver::WaitHandle() const
{
    return m_event.get();
}

void AuthorizationStateReceiver::Signal()
{
    if (m_event && !SetEvent(m_event.get()))
    {
        LogHandleFailure(m_logger, tailgate::base::LogLevel::Warning, "SetEvent", GetLastError());
    }
}

void AuthorizationStateReceiver::Cancel()
{
    if (!m_view || !m_cancelEvent)
    {
        return;
    }
    auto* view = static_cast<AuthorizationMapping*>(m_view.get());
    InterlockedExchange(&view->CancelRequested, 1);
    if (!SetEvent(m_cancelEvent.get()))
    {
        LogHandleFailure(
            m_logger, tailgate::base::LogLevel::Warning, "SetEvent(cancel)", GetLastError());
        return;
    }
    m_logger.LogInfo("foreground cancelled the active connection attempt");
}

ConnectionCancellationMonitor::ConnectionCancellationMonitor(
    const winrt::hstring& expectedTailgateServer)
{
    const std::string expectedServer = winrt::to_string(expectedTailgateServer);
    winrt::handle mapping(
        OpenFileMappingFromApp(FILE_MAP_ALL_ACCESS, FALSE, AuthorizationMappingName));
    if (!mapping)
    {
        return;
    }
    MappedView mappedView(
        MapViewOfFileFromApp(mapping.get(), FILE_MAP_ALL_ACCESS, 0, sizeof(AuthorizationMapping)));
    if (!mappedView)
    {
        return;
    }
    auto* view = static_cast<AuthorizationMapping*>(mappedView.get());
    const bool validMapping = view->Magic == AuthorizationMappingMagic &&
                              view->Version == AuthorizationMappingVersion &&
                              view->ForegroundProcessId != 0 && view->TailgateServerLength != 0 &&
                              view->TailgateServerLength <= view->TailgateServer.size();
    const std::string activeServer =
        validMapping ? std::string(view->TailgateServer.data(), view->TailgateServerLength)
                     : std::string{};
    if (!validMapping || activeServer != expectedServer)
    {
        return;
    }
    winrt::handle cancelEvent(OpenEventW(SYNCHRONIZE, FALSE, AuthorizationCancelEventName));
    if (!cancelEvent)
    {
        return;
    }
    winrt::handle foregroundProcess(OpenProcess(SYNCHRONIZE, FALSE, view->ForegroundProcessId));
    if (!foregroundProcess)
    {
        return;
    }
    m_mapping = std::move(mapping);
    m_view = std::move(mappedView);
    m_cancelEvent = std::move(cancelEvent);
    m_foregroundProcess = std::move(foregroundProcess);
}

ConnectionCancellationMonitor::~ConnectionCancellationMonitor() = default;

bool ConnectionCancellationMonitor::Available() const noexcept
{
    return m_view && m_cancelEvent && m_foregroundProcess;
}

ConnectionCancellationReason ConnectionCancellationMonitor::Wait(void* stopHandle) const
{
    if (!Available() || stopHandle == nullptr)
    {
        return ConnectionCancellationReason::Unavailable;
    }
    auto* view = static_cast<AuthorizationMapping*>(m_view.get());
    if (InterlockedCompareExchange(&view->CancelRequested, 0, 0) != 0)
    {
        return ConnectionCancellationReason::Cancelled;
    }
    const std::array<HANDLE, 3> handles{
        m_cancelEvent.get(),
        m_foregroundProcess.get(),
        static_cast<HANDLE>(stopHandle),
    };
    const DWORD result =
        WaitForMultipleObjects(static_cast<DWORD>(handles.size()), handles.data(), FALSE, INFINITE);
    if (result == WAIT_OBJECT_0)
    {
        return ConnectionCancellationReason::Cancelled;
    }
    if (result == WAIT_OBJECT_0 + 1)
    {
        return ConnectionCancellationReason::ForegroundExited;
    }
    if (result == WAIT_OBJECT_0 + 2)
    {
        return ConnectionCancellationReason::MonitorStopped;
    }
    LogHandleFailure(m_logger,
                     tailgate::base::LogLevel::Warning,
                     "WaitForMultipleObjects(connection cancellation)",
                     GetLastError());
    return ConnectionCancellationReason::Unavailable;
}

bool PublishConnectionMessage(const ConnectionMessage& message)
{
    const std::string url = winrt::to_string(message.Url);
    const std::string tailgateServer = winrt::to_string(message.TailgateServer);
    if (!IsMessageKindValid(static_cast<std::uint32_t>(message.Kind)) || tailgateServer.empty() ||
        url.size() > AuthorizationUrlCapacity ||
        !IsMessageContentValid(message.Kind, url.size(), message.ErrorCode))
    {
        AuthorizationPublisherLogger.LogError(
            "background connection-attempt message exceeds the queue format");
        return false;
    }
    winrt::handle mapping(
        OpenFileMappingFromApp(FILE_MAP_ALL_ACCESS, FALSE, AuthorizationMappingName));
    if (!mapping)
    {
        const DWORD error = GetLastError();
        LogHandleFailure(AuthorizationPublisherLogger,
                         error == ERROR_FILE_NOT_FOUND ? tailgate::base::LogLevel::Debug
                                                       : tailgate::base::LogLevel::Warning,
                         "OpenFileMappingFromApp",
                         error);
        return false;
    }
    MappedView mappedView(
        MapViewOfFileFromApp(mapping.get(), FILE_MAP_ALL_ACCESS, 0, sizeof(AuthorizationMapping)));
    if (!mappedView)
    {
        const DWORD error = GetLastError();
        LogHandleFailure(AuthorizationPublisherLogger,
                         tailgate::base::LogLevel::Warning,
                         "MapViewOfFileFromApp",
                         error);
        return false;
    }
    auto* view = static_cast<AuthorizationMapping*>(mappedView.get());
    const bool validMapping = view->Magic == AuthorizationMappingMagic &&
                              view->Version == AuthorizationMappingVersion &&
                              view->TailgateServerLength != 0 &&
                              view->TailgateServerLength <= view->TailgateServer.size();
    const std::string expectedServer =
        validMapping ? std::string(view->TailgateServer.data(), view->TailgateServerLength)
                     : std::string{};
    if (!validMapping || tailgateServer != expectedServer)
    {
        AuthorizationPublisherLogger.LogWarning(
            "background rejected an inactive connection-attempt queue");
        return false;
    }
    const LONG nextSequence = InterlockedCompareExchange(&view->WriteSequence, 0, 0) + 1;
    const std::size_t index =
        (static_cast<std::uint32_t>(nextSequence) - 1U) % AuthorizationQueueCapacity;
    AuthorizationMessageSlot& slot = view->Messages[index];
    InterlockedExchange(&slot.Sequence, 0);
    slot.Kind = static_cast<std::uint32_t>(message.Kind);
    slot.UrlLength = static_cast<std::uint32_t>(url.size());
    slot.ErrorCode = static_cast<std::uint32_t>(message.ErrorCode);
    if (!url.empty())
    {
        std::memcpy(slot.Url.data(), url.data(), url.size());
    }
    MemoryBarrier();
    InterlockedExchange(&slot.Sequence, nextSequence);
    InterlockedExchange(&view->WriteSequence, nextSequence);
    mappedView.close();
    mapping.close();

    winrt::handle event(OpenEventW(EVENT_MODIFY_STATE, FALSE, AuthorizationEventName));
    if (!event)
    {
        LogHandleFailure(AuthorizationPublisherLogger,
                         tailgate::base::LogLevel::Warning,
                         "OpenEventW",
                         GetLastError());
        return false;
    }
    const bool signaled = SetEvent(event.get()) != FALSE;
    if (!signaled)
    {
        LogHandleFailure(AuthorizationPublisherLogger,
                         tailgate::base::LogLevel::Warning,
                         "SetEvent",
                         GetLastError());
    }
    AuthorizationPublisherLogger.LogDebug("background queued connection-attempt message kind={}",
                                          static_cast<std::uint32_t>(message.Kind));
    return signaled;
}

} // namespace tailgate::uwp
