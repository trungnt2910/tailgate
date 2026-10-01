#include "app/controller/impl/ModeRpcControllerImpl.h"

#include <atomic>
#include <mutex>
#include <utility>

#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Storage.Streams.h>

#include <tailgate/base/Logger.h>

#include "common/EventLoop.h"
#include "common/VpnConstants.h"

namespace tailgate::uwp
{

class ModeRpcOperation final
{
public:
    void Store(app_service::ModeResponse response)
    {
        {
            std::lock_guard lock(Mutex);
            Response = std::move(response);
        }
        Events.Wake();
    }

    std::optional<app_service::ModeResponse> Take()
    {
        std::lock_guard lock(Mutex);
        return std::exchange(Response, std::nullopt);
    }

    void Cancel()
    {
        Cancelled = true;
        Events.Wake();
    }

    EventLoop Events;
    std::atomic_bool Cancelled = false;
    std::uint64_t Sequence = 0;

private:
    std::mutex Mutex;
    std::optional<app_service::ModeResponse> Response;
};

ModeRpcControllerImpl::ModeRpcControllerImpl(tailgate::base::TimeProvider& time) : m_time(time)
{
}

ModeRpcControllerImpl::~ModeRpcControllerImpl()
{
    if (m_operation)
    {
        m_operation->Cancel();
    }
}

const ModeRpcState& ModeRpcControllerImpl::GetState() const noexcept
{
    return m_state;
}

void ModeRpcControllerImpl::Request(const winrt::hstring& selfAddress,
                                    const winrt::hstring& relayUrl)
{
    if (m_operation)
    {
        m_operation->Cancel();
    }
    static std::atomic_uint64_t sequence = 0;
    m_operation = std::make_shared<ModeRpcOperation>();
    m_operation->Sequence = ++sequence;
    m_state.Response(std::nullopt);
    (void)Run(selfAddress, relayUrl, m_operation);
}

FireAndForget ModeRpcControllerImpl::Run(winrt::hstring selfAddress,
                                         winrt::hstring relayUrl,
                                         std::shared_ptr<ModeRpcOperation> operation)
{
    namespace sockets = winrt::Windows::Networking::Sockets;
    namespace streams = winrt::Windows::Storage::Streams;
    winrt::apartment_context ui;
    const auto deadline = m_time.Now() + std::chrono::seconds(60);
    auto timer = m_time.At(deadline);
    co_await winrt::resume_background();
    app_service::ModeResponse last{
        .Result = app_service::Status::Timeout, .Sequence = operation->Sequence, .Transition = {}};
    try
    {
        sockets::DatagramSocket socket;
        socket.MessageReceived(
            [weak = std::weak_ptr(operation)](const auto&, const auto& args)
            {
                const auto state = weak.lock();
                if (!state || state->Cancelled)
                {
                    return;
                }
                try
                {
                    const auto reader = args.GetDataReader();
                    std::vector<std::uint8_t> bytes(reader.UnconsumedBufferLength());
                    reader.ReadBytes(bytes);
                    const auto message = app_service::DecodeMessage(bytes);
                    const auto response =
                        message ? app_service::DecodeModeResponse(*message) : std::nullopt;
                    if (response && response->Sequence == state->Sequence)
                    {
                        state->Store(*response);
                    }
                }
                catch (const winrt::hresult_error&)
                {
                    tailgate::base::Logger("uwp-mode-rpc")
                        .LogWarning("discarding unreadable mode response");
                }
            });
        const networking::EndpointPair endpoints(
            networking::HostName(selfAddress),
            L"",
            networking::HostName(VpnConstants::Network::ServiceHost),
            winrt::to_hstring(VpnConstants::AppService::Port));
        socket.ConnectAsync(endpoints).get();
        streams::DataWriter writer(socket.OutputStream());
        writer.WriteBytes(app_service::EncodeModeRequest(
            {.Sequence = operation->Sequence, .RelayUrl = winrt::to_string(relayUrl)}));
        (void)writer.StoreAsync().get();
        while (!operation->Cancelled)
        {
            const auto wait = operation->Events.Wait(*timer, 1);
            if (operation->Cancelled)
            {
                co_return;
            }
            const auto response = operation->Take();
            if (!response || wait.Status == tailgate::base::EventWaitStatus::DeadlineReached)
            {
                if (wait.Status == tailgate::base::EventWaitStatus::DeadlineReached)
                {
                    break;
                }
                continue;
            }
            last = *response;
            co_await ui;
            if (operation->Cancelled)
            {
                co_return;
            }
            m_state.Response(last);
            using tailgate::ipn::ipnlocal::TransitionPhase;
            if (last.Result != app_service::Status::Ok ||
                last.Transition.Phase == TransitionPhase::Idle ||
                last.Transition.Phase == TransitionPhase::Failed)
            {
                co_return;
            }
            co_await winrt::resume_background();
        }
    }
    catch (...)
    {
        tailgate::base::Logger("uwp-mode-rpc").LogWarning("mode request transport failed");
    }
    last.Result = app_service::Status::Timeout;
    co_await ui;
    if (!operation->Cancelled)
    {
        m_state.Response(last);
    }
}

} // namespace tailgate::uwp
