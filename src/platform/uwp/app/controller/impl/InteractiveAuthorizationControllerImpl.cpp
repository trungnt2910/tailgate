#include "app/controller/impl/InteractiveAuthorizationControllerImpl.h"

#include <exception>
#include <utility>
#include <vector>

#include "common/AuthorizationState.h"

namespace tailgate::uwp
{

InteractiveAuthorizationControllerImpl::~InteractiveAuthorizationControllerImpl() = default;

const InteractiveAuthorizationState&
InteractiveAuthorizationControllerImpl::GetState() const noexcept
{
    return m_state;
}

void InteractiveAuthorizationControllerImpl::Listen(const winrt::hstring& tailgateServer)
{
    if (m_receiver)
    {
        m_pendingTailgateServer = tailgateServer;
        m_stopRequested = true;
        m_receiver->Signal();
        return;
    }
    StartListening(tailgateServer);
}

void InteractiveAuthorizationControllerImpl::Stop()
{
    m_pendingTailgateServer.clear();
    if (!m_receiver)
    {
        return;
    }
    m_stopRequested = true;
    m_receiver->Signal();
}

void InteractiveAuthorizationControllerImpl::Cancel()
{
    if (!m_receiver)
    {
        return;
    }
    m_receiver->Cancel();
    m_state.Status(InteractiveAuthorizationStatus::Cancelled);
}

void InteractiveAuthorizationControllerImpl::StartListening(const winrt::hstring& tailgateServer)
{
    try
    {
        m_receiver = std::make_unique<AuthorizationStateReceiver>(tailgateServer);
        m_stopRequested = false;
        m_state.Update(
            [&](InteractiveAuthorizationState& state)
            {
                state.Status(InteractiveAuthorizationStatus::Listening);
                state.Url(L"");
                state.TailgateServer(tailgateServer);
                state.Error(std::nullopt);
            });
        (void)Monitor(m_receiver.get());
    }
    catch (const winrt::hresult_error& error)
    {
        m_receiver.reset();
        m_state.Update(
            [&](InteractiveAuthorizationState& state)
            {
                state.Status(InteractiveAuthorizationStatus::Failed);
                state.TailgateServer(tailgateServer);
                state.Error(
                    UwpError::FromHresult(error.code()).value_or(UwpError::Code::Unexpected));
            });
        m_logger.LogError("failed to listen for authorization: {}", error.message());
    }
}

FireAndForget InteractiveAuthorizationControllerImpl::Monitor(AuthorizationStateReceiver* receiver)
{
    winrt::apartment_context uiThread;
    std::optional<UwpError::Code> failure;
    try
    {
        while (m_receiver.get() == receiver)
        {
            co_await winrt::resume_on_signal(receiver->WaitHandle());
            co_await uiThread;
            if (m_receiver.get() != receiver)
            {
                co_return;
            }
            if (m_stopRequested)
            {
                const winrt::hstring pending = std::exchange(m_pendingTailgateServer, {});
                m_receiver.reset();
                m_stopRequested = false;
                m_state.Update(
                    [](InteractiveAuthorizationState& state)
                    {
                        state.Status(InteractiveAuthorizationStatus::Idle);
                        state.Url(L"");
                        state.Error(std::nullopt);
                    });
                if (!pending.empty())
                {
                    StartListening(pending);
                }
                co_return;
            }
            const std::vector<ConnectionMessage> messages = receiver->ReadAvailable();
            for (const ConnectionMessage& message : messages)
            {
                Publish(message);
            }
        }
    }
    catch (const winrt::hresult_error& error)
    {
        failure = UwpError::FromHresult(error.code()).value_or(UwpError::Code::Unexpected);
        m_logger.LogError("authorization listener failed: {}", error.message());
    }
    catch (const std::exception& error)
    {
        failure = UwpError::Code::Unexpected;
        m_logger.LogError("authorization listener failed: {}", error.what());
    }

    co_await uiThread;
    if (m_receiver.get() != receiver)
    {
        co_return;
    }
    const winrt::hstring pending = std::exchange(m_pendingTailgateServer, {});
    m_receiver.reset();
    m_stopRequested = false;
    m_state.Update(
        [&](InteractiveAuthorizationState& state)
        {
            state.Status(InteractiveAuthorizationStatus::Failed);
            state.Error(failure);
        });
    if (!pending.empty())
    {
        StartListening(pending);
    }
}

void InteractiveAuthorizationControllerImpl::Publish(const ConnectionMessage& message)
{
    m_state.Update(
        [&](InteractiveAuthorizationState& state)
        {
            state.TailgateServer(message.TailgateServer);
            state.Url(message.Url);
            switch (message.Kind)
            {
            case ConnectionMessageKind::LoginRequired:
                state.Status(InteractiveAuthorizationStatus::LoginRequired);
                state.Error(std::nullopt);
                break;
            case ConnectionMessageKind::MachineApprovalRequired:
                state.Status(InteractiveAuthorizationStatus::MachineApprovalRequired);
                state.Error(std::nullopt);
                break;
            case ConnectionMessageKind::ControlAuthorized:
                state.Status(InteractiveAuthorizationStatus::Authorized);
                state.Error(std::nullopt);
                break;
            case ConnectionMessageKind::Failed:
                state.Status(InteractiveAuthorizationStatus::Failed);
                state.Error(message.ErrorCode);
                break;
            }
        });
}

} // namespace tailgate::uwp
