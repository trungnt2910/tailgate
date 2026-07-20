#include "app/controller/impl/PingControllerImpl.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Storage.Streams.h>
#include <winrt/Windows.UI.Core.h>

#include <tailgate/Logger.h>

#include "common/UwpAppServiceProtocol.h"
#include "common/UwpFireAndForget.h"
#include "common/UwpFormat.h"
#include "common/VpnConstants.h"

namespace tailgate::uwp
{
namespace sockets = winrt::Windows::Networking::Sockets;
namespace streams = winrt::Windows::Storage::Streams;
namespace ui_core = winrt::Windows::UI::Core;

using namespace std::chrono_literals;

struct PingSessionState
{
    std::atomic_bool Active = true;
    std::string Address;
    winrt::hstring SelfAddress;
    PingState* State = nullptr;
    ui_core::CoreDispatcher Dispatcher{nullptr};
    xaml::DispatcherTimer TickTimer;
    sockets::DatagramSocket Socket{nullptr};
    streams::DataWriter Writer{nullptr};
    std::deque<std::vector<std::uint8_t>> PendingWrites;
    std::unordered_set<std::uint64_t> PendingSequences;
    std::uint64_t NextSequence = 1;
    int TicksSent = 0;
    bool Writing = false;
    bool ReceivedResponse = false;
    bool TimeoutReported = false;
    std::chrono::steady_clock::time_point Started{};
    std::chrono::steady_clock::time_point LastSent{};
    Logger Log{"uwp-ping-session"};
};

namespace
{

enum class PingResultStatus
{
    Success,
    NoMatchingPeer,
    Timeout,
    Failed,
};

struct PingResult
{
    PingResultStatus Status = PingResultStatus::Failed;
    double LatencyMilliseconds = 0;
    bool Direct = false;
    winrt::hstring Relay;
};

constexpr int PingCount = 10;
constexpr std::chrono::seconds PingTickInterval(1);
constexpr std::chrono::seconds PingResponseTimeout(5);

void StopSession(const std::shared_ptr<PingSessionState>& state) noexcept
{
    if (!state->Active.exchange(false))
    {
        return;
    }
    try
    {
        state->TickTimer.Stop();
        state->PendingWrites.clear();
        state->PendingSequences.clear();
        state->Writer = nullptr;
        if (state->Socket != nullptr)
        {
            state->Socket.Close();
            state->Socket = nullptr;
        }
    }
    catch (const winrt::hresult_error& error)
    {
        state->Log.LogWarning("session cleanup failed: {}", error.message());
    }
}

void ApplyResult(PingState& state, const PingResult& result)
{
    switch (result.Status)
    {
    case PingResultStatus::Success:
    {
        std::vector<double> samples = state.Samples();
        samples.push_back(result.LatencyMilliseconds);
        state.Update(
            [&](PingState& updated)
            {
                updated.Samples(std::move(samples));
                updated.LatencyMilliseconds(result.LatencyMilliseconds);
                updated.Direct(result.Direct);
                updated.Relay(result.Relay);
                updated.Status(PingStatus::Success);
            });
        return;
    }
    case PingResultStatus::NoMatchingPeer:
        state.Status(PingStatus::NoMatchingPeer);
        return;
    case PingResultStatus::Timeout:
        state.Status(PingStatus::Timeout);
        return;
    case PingResultStatus::Failed:
        state.Status(PingStatus::Failed);
        return;
    }
}

void DeliverResponse(const std::shared_ptr<PingSessionState>& state,
                     std::uint64_t sequence,
                     PingResult result)
{
    const std::weak_ptr<PingSessionState> weakState(state);
    (void)state->Dispatcher.RunAsync(
        ui_core::CoreDispatcherPriority::Normal,
        [weakState, sequence, result = std::move(result)]
        {
            const std::shared_ptr<PingSessionState> current = weakState.lock();
            if (!current || !current->Active || current->PendingSequences.erase(sequence) == 0)
            {
                return;
            }
            current->ReceivedResponse = true;
            ApplyResult(*current->State, result);
        });
}

void HandlePingResponse(const std::weak_ptr<PingSessionState>& weakState,
                        const sockets::DatagramSocketMessageReceivedEventArgs& arguments)
{
    const std::shared_ptr<PingSessionState> state = weakState.lock();
    if (!state || !state->Active)
    {
        return;
    }
    try
    {
        const streams::DataReader reader = arguments.GetDataReader();
        state->Log.LogTrace("response datagram bytes={}", reader.UnconsumedBufferLength());
        std::vector<std::uint8_t> payload(reader.UnconsumedBufferLength());
        reader.ReadBytes(payload);
        const std::optional<app_service::Message> message = app_service::DecodeMessage(payload);
        const std::optional<app_service::PingResponse> response =
            message ? app_service::DecodePingResponse(*message) : std::nullopt;
        if (!response)
        {
            return;
        }

        PingResult result;
        result.Status = response->Result == app_service::Status::Ok ? PingResultStatus::Success
                        : response->Result == app_service::Status::NoMatchingPeer
                            ? PingResultStatus::NoMatchingPeer
                            : PingResultStatus::Failed;
        result.LatencyMilliseconds = static_cast<double>(response->LatencyMicroseconds) / 1000.0;
        result.Direct = response->Direct;
        result.Relay = winrt::to_hstring(response->Relay);
        DeliverResponse(state, response->Sequence, std::move(result));
    }
    catch (const winrt::hresult_error& error)
    {
        state->Log.LogWarning("response parse failed: {}", error.message());
    }
}

FireAndForget FlushWritesAsync(std::shared_ptr<PingSessionState> state)
{
    try
    {
        while (state->Active && state->Writer != nullptr && !state->PendingWrites.empty())
        {
            std::vector<std::uint8_t> payload = std::move(state->PendingWrites.front());
            state->PendingWrites.pop_front();
            state->Writer.WriteBytes(winrt::array_view(payload));
            (void)co_await state->Writer.StoreAsync();
        }
    }
    catch (const winrt::hresult_error& error)
    {
        if (state->Active)
        {
            state->Log.LogWarning("request send failed: {}", error.message());
        }
    }
    catch (const std::exception& error)
    {
        if (state->Active)
        {
            state->Log.LogWarning("request encoding failed: {}", error.what());
        }
    }
    state->Writing = false;
}

void SendPingRequest(const std::shared_ptr<PingSessionState>& state)
{
    ++state->TicksSent;
    state->LastSent = std::chrono::steady_clock::now();
    if (state->Writer == nullptr)
    {
        return;
    }

    const std::uint64_t sequence = state->NextSequence++;
    std::vector<std::uint8_t> request = app_service::EncodePingRequest(app_service::PingRequest{
        .Sequence = sequence,
        .Target = state->Address,
    });
    state->PendingSequences.insert(sequence);
    state->PendingWrites.push_back(std::move(request));
    if (!state->Writing)
    {
        state->Writing = true;
        FlushWritesAsync(state);
    }
}

void OnTick(const std::shared_ptr<PingSessionState>& state)
{
    if (state->TicksSent < PingCount)
    {
        SendPingRequest(state);
    }

    const auto now = std::chrono::steady_clock::now();
    if (!state->ReceivedResponse && !state->TimeoutReported &&
        now - state->Started > PingResponseTimeout)
    {
        state->TimeoutReported = true;
        PingResult result;
        result.Status = PingResultStatus::Timeout;
        ApplyResult(*state->State, result);
    }
    if (state->TicksSent >= PingCount && now - state->LastSent > PingResponseTimeout)
    {
        state->TickTimer.Stop();
    }
}

FireAndForget StartSocketAsync(std::shared_ptr<PingSessionState> state)
{
    try
    {
        const sockets::DatagramSocket socket;
        state->Socket = socket;
        socket.MessageReceived(
            [weakState = std::weak_ptr<PingSessionState>(state)](
                const auto&, const sockets::DatagramSocketMessageReceivedEventArgs& arguments)
            {
                HandlePingResponse(weakState, arguments);
            });
        if (state->SelfAddress.empty())
        {
            co_await socket.ConnectAsync(networking::HostName(VpnConstants::Network::ServiceHost),
                                         winrt::to_hstring(VpnConstants::AppService::Port));
        }
        else
        {
            const networking::EndpointPair endpoints(
                networking::HostName(state->SelfAddress),
                L"",
                networking::HostName(VpnConstants::Network::ServiceHost),
                winrt::to_hstring(VpnConstants::AppService::Port));
            co_await socket.ConnectAsync(endpoints);
        }
        co_await winrt::resume_foreground(state->Dispatcher);
        if (!state->Active || state->TicksSent >= PingCount)
        {
            co_return;
        }
        state->Writer = streams::DataWriter(socket.OutputStream());
        SendPingRequest(state);
    }
    catch (const winrt::hresult_error& error)
    {
        if (state->Active)
        {
            state->Log.LogDebug("socket connect failed: {}", error.message());
        }
    }
}

} // namespace

PingControllerImpl::~PingControllerImpl()
{
    Stop();
}

const PingState& PingControllerImpl::GetState() const noexcept
{
    return m_state;
}

void PingControllerImpl::Start(const winrt::hstring& address, const winrt::hstring& selfAddress)
{
    Stop();
    m_state.Update(
        [](PingState& state)
        {
            state.Samples({});
            state.LatencyMilliseconds(0);
            state.Direct(false);
            state.Relay({});
            state.Status(PingStatus::Starting);
        });
    auto state = std::make_shared<PingSessionState>();
    state->Address = winrt::to_string(address);
    state->SelfAddress = selfAddress;
    state->State = &m_state;
    state->Dispatcher = xaml::Window::Current().Dispatcher();
    state->Started = std::chrono::steady_clock::now();
    state->TickTimer.Interval(PingTickInterval);
    state->TickTimer.Tick(
        [weakState = std::weak_ptr<PingSessionState>(state)](const auto&, const auto&)
        {
            const std::shared_ptr<PingSessionState> current = weakState.lock();
            if (current && current->Active)
            {
                OnTick(current);
            }
        });
    state->TickTimer.Start();
    StartSocketAsync(state);
    m_session = std::move(state);
}

void PingControllerImpl::Stop() noexcept
{
    if (m_session)
    {
        StopSession(m_session);
        m_session.reset();
    }
}

} // namespace tailgate::uwp
