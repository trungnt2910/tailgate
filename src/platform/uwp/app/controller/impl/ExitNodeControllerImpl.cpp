#include "app/controller/impl/ExitNodeControllerImpl.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Storage.Streams.h>

#include "common/EventSignal.h"
#include "common/UwpAppServiceProtocol.h"
#include "common/VpnConstants.h"

#include "app/controller/SessionController.h"
#include "app/controller/SettingsController.h"

namespace tailgate::uwp
{

class ExitNodeChangeState
{
public:
    explicit ExitNodeChangeState(std::uint64_t expectedSequence) : m_sequence(expectedSequence)
    {
    }

    [[nodiscard]] std::uint64_t Sequence() const noexcept
    {
        return m_sequence;
    }

    void StoreResponse(app_service::ExitNodeResponse response)
    {
        {
            std::lock_guard lock(m_mutex);
            m_response = std::move(response);
        }
        m_responseEvent.Set();
    }

    [[nodiscard]] std::optional<app_service::ExitNodeResponse> Response()
    {
        std::lock_guard lock(m_mutex);
        return m_response;
    }

    [[nodiscard]] HANDLE ResponseHandle() const noexcept
    {
        return m_responseEvent.Handle();
    }

    void Result(ExitNodeChangeStatus result) noexcept
    {
        m_result = result;
    }

    [[nodiscard]] ExitNodeChangeStatus Result() const noexcept
    {
        return m_result;
    }

private:
    std::mutex m_mutex;
    std::optional<app_service::ExitNodeResponse> m_response;
    ExitNodeChangeStatus m_result = ExitNodeChangeStatus::Failed;
    std::uint64_t m_sequence = 0;
    EventSignal m_responseEvent;
};

namespace
{

namespace sockets = winrt::Windows::Networking::Sockets;
namespace streams = winrt::Windows::Storage::Streams;

using namespace std::chrono_literals;

constexpr std::chrono::seconds ExitNodeChangeTimeout(60);

std::uint64_t NextExitNodeSequence()
{
    static std::atomic_uint64_t sequence = 0;
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return static_cast<std::uint64_t>(now) + ++sequence;
}

void HandleExitNodeResponse(const tailgate::base::Logger& logger,
                            const std::weak_ptr<ExitNodeChangeState>& weakState,
                            const sockets::DatagramSocketMessageReceivedEventArgs& arguments)
{
    const std::shared_ptr<ExitNodeChangeState> state = weakState.lock();
    if (!state)
    {
        return;
    }
    try
    {
        const streams::DataReader reader = arguments.GetDataReader();
        std::vector<std::uint8_t> payload(reader.UnconsumedBufferLength());
        reader.ReadBytes(payload);
        const std::optional<app_service::Message> message = app_service::DecodeMessage(payload);
        const std::optional<app_service::ExitNodeResponse> response =
            message ? app_service::DecodeExitNodeResponse(*message) : std::nullopt;
        if (!response || response->Sequence != state->Sequence())
        {
            return;
        }
        state->StoreResponse(std::move(*response));
    }
    catch (const winrt::hresult_error& error)
    {
        logger.LogWarning("failed to parse response: {}", error.message());
    }
}

} // namespace

ExitNodeControllerImpl::ExitNodeControllerImpl(SessionController& sessionController,
                                               SettingsController& settingsController)
    : m_sessionController(sessionController), m_settingsController(settingsController)
{
    Reload();
    m_settingsRegistration = settingsController.GetState().Subscribe(
        [this](const auto&, const auto&)
        {
            Reload();
        });
}

const ExitNodeState& ExitNodeControllerImpl::GetState() const noexcept
{
    return m_state;
}

void ExitNodeControllerImpl::Reload()
{
    const winrt::hstring current = m_settingsController.GetState().ExitNode();
    const winrt::hstring selected = m_settingsController.GetState().ExitNodeSelection();
    m_state.Update(
        [&](ExitNodeState& state)
        {
            state.Current(current);
            state.Selection(selected.empty() ? current : selected);
        });
}

void ExitNodeControllerImpl::SetNode(const winrt::hstring& nodeName)
{
    StartChange(ValidateNode(nodeName), false);
}

void ExitNodeControllerImpl::SetNodeForNextConnection(const winrt::hstring& nodeName)
{
    m_settingsController.SetExitNode(ValidateNode(nodeName), false);
}

void ExitNodeControllerImpl::SetEnabled(bool enabled)
{
    StartChange(enabled ? m_state.Selection() : winrt::hstring{}, true);
}

winrt::hstring ExitNodeControllerImpl::ValidateNode(const winrt::hstring& nodeName) const
{
    if (nodeName.empty())
    {
        return {};
    }
    const bool known = std::any_of(m_settingsController.GetState().Devices().begin(),
                                   m_settingsController.GetState().Devices().end(),
                                   [&nodeName](const UwpDevice& device)
                                   {
                                       return device.MatchesExitNode(nodeName);
                                   });
    if (known)
    {
        return nodeName;
    }
    m_logger.LogWarning("unavailable exit node; falling back to none: {}", nodeName);
    return {};
}

void ExitNodeControllerImpl::StartChange(winrt::hstring nodeName, bool preserveSelection)
{
    const SessionState& session = m_sessionController.GetState();
    if (session.ConnectionOperationActive())
    {
        return;
    }
    m_logger.LogInfo("requesting exit node: {}",
                     nodeName.empty() ? winrt::hstring(L"<none>") : nodeName);
    if (!session.Connected())
    {
        m_settingsController.SetExitNode(nodeName, preserveSelection);
        Reload();
        return;
    }
    m_settingsController.Reload();
    winrt::hstring selfAddress = m_settingsController.GetState().SelfAddress();
    if (selfAddress.empty() && !m_settingsController.GetState().Devices().empty())
    {
        selfAddress = m_settingsController.GetState().Devices().front().Address();
    }
    m_sessionController.BeginExitNodeChange();
    if (selfAddress.empty())
    {
        m_sessionController.FinishExitNodeChange(UwpError::Code::VpnAddressUnavailable);
        return;
    }
    (void)ChangeAsync(std::move(nodeName), preserveSelection, std::move(selfAddress));
}

FireAndForget ExitNodeControllerImpl::ChangeAsync(winrt::hstring nodeName,
                                                  bool preserveSelection,
                                                  winrt::hstring selfAddress)
{
    winrt::apartment_context uiThread;
    const auto state = std::make_shared<ExitNodeChangeState>(NextExitNodeSequence());
    // resume_on_signal completes the request on a thread-pool thread. Keep its result detached
    // from observable state, then return here before notifying controllers and XAML views.
    co_await winrt::resume_agile(
        RequestChangeAsync(std::move(nodeName), preserveSelection, std::move(selfAddress), state));
    co_await uiThread;

    const ExitNodeChangeStatus result = state->Result();
    m_state.ChangeStatus(result);
    Reload();
    std::optional<UwpError::Code> error;
    switch (result)
    {
    case ExitNodeChangeStatus::Success:
        break;
    case ExitNodeChangeStatus::Rejected:
        error = UwpError::Code::ExitNodeRejected;
        break;
    case ExitNodeChangeStatus::Timeout:
        error = UwpError::Code::VpnBackgroundRestartTimedOut;
        break;
    case ExitNodeChangeStatus::Failed:
        error = UwpError::Code::ExitNodeFailed;
        break;
    }
    m_sessionController.FinishExitNodeChange(error);
}

foundation::IAsyncAction
ExitNodeControllerImpl::RequestChangeAsync(winrt::hstring nodeName,
                                           bool preserveSelection,
                                           winrt::hstring selfAddress,
                                           std::shared_ptr<ExitNodeChangeState> state)
{
    try
    {
        const sockets::DatagramSocket socket;
        socket.MessageReceived(
            [logger = m_logger, weakState = std::weak_ptr<ExitNodeChangeState>(state)](
                const auto&, const sockets::DatagramSocketMessageReceivedEventArgs& arguments)
            {
                HandleExitNodeResponse(logger, weakState, arguments);
            });
        const networking::EndpointPair endpoints(
            networking::HostName(selfAddress),
            L"",
            networking::HostName(VpnConstants::Network::ServiceHost),
            winrt::to_hstring(VpnConstants::AppService::Port));
        co_await socket.ConnectAsync(endpoints);
        streams::DataWriter writer(socket.OutputStream());
        const std::vector<std::uint8_t> request =
            app_service::EncodeExitNodeRequest(app_service::ExitNodeRequest{
                .Sequence = state->Sequence(),
                .ExitNode = winrt::to_string(nodeName),
                .PreserveSelection = preserveSelection,
            });
        writer.WriteBytes(winrt::array_view(request));
        (void)co_await writer.StoreAsync();
        co_await winrt::resume_on_signal(state->ResponseHandle(), ExitNodeChangeTimeout);

        const std::optional<app_service::ExitNodeResponse> response = state->Response();
        if (!response)
        {
            state->Result(ExitNodeChangeStatus::Timeout);
            co_return;
        }
        if (response->Result != app_service::Status::Ok)
        {
            state->Result(ExitNodeChangeStatus::Rejected);
            co_return;
        }
        m_logger.LogInfo("background restart completed exit-node={}",
                         response->ExitNode.empty() ? "<none>" : response->ExitNode.c_str());
        state->Result(ExitNodeChangeStatus::Success);
        co_return;
    }
    catch (const winrt::hresult_error& error)
    {
        const bool timeout = error.code() == HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        m_logger.LogWarning("change failed hresult={} message={}", error.code(), error.message());
        state->Result(timeout ? ExitNodeChangeStatus::Timeout : ExitNodeChangeStatus::Failed);
    }
    catch (const std::exception& error)
    {
        m_logger.LogWarning("change failed: {}", error.what());
        state->Result(ExitNodeChangeStatus::Failed);
    }
}

} // namespace tailgate::uwp
