#include "DerpWakeTransport.h"

#include <array>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string_view>
#include <thread>
#include <utility>

#include <winrt/Windows.Networking.h>

#include <tailgate/base/Logger.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/derp/Client.h>

#include "common/ThreadApartment.h"
#include "common/UwpFormat.h"
#include "common/UwpStreamIo.h"
#include "common/WinrtOperation.h"

#include "VpnCallbackStream.h"

namespace tailgate::uwp::bg
{
namespace
{
namespace sockets = winrt::Windows::Networking::Sockets;
// Incoming traffic on an associated network socket activates the legacy VPN host.
// The loopback pulse alone does not reliably do so on build 15035.
constexpr auto PingInterval = std::chrono::seconds(1);
constexpr auto IoTimeout = std::chrono::seconds(10);

} // namespace

struct DerpWakeTransport::State
{
    sockets::StreamSocket Socket;
    std::stop_source Cancellation;
    std::unique_ptr<UwpStreamIo> Io;
    std::unique_ptr<VpnCallbackStream> Stream;
    std::unique_ptr<derp::DerpClient> Client;
    std::jthread Worker;
    std::mutex Mutex;
    std::condition_variable_any Ready;
    bool Closed = false;
    base::Logger Logger{"derp-wake"};

    void Run(std::stop_token stop)
    {
        const std::stop_callback cancelIo(stop,
                                          [this]
                                          {
                                              Cancellation.request_stop();
                                          });
        try
        {
            ThreadApartment::Ensure();
            auto next = std::chrono::steady_clock::now();
            std::uint64_t sequence = 0;
            while (!stop.stop_requested())
            {
                std::unique_lock lock(Mutex);
                Ready.wait_until(lock,
                                 stop,
                                 next,
                                 [this]
                                 {
                                     return Closed || Client->HasBufferedInput();
                                 });
                if (Closed || stop.stop_requested())
                {
                    break;
                }
                lock.unlock();
                // Core handles framing, partial frames and responses to server pings.
                // This independent identity carries no tailnet data packets.
                (void)Client->ReceiveAvailableBatch();
                if (std::chrono::steady_clock::now() >= next)
                {
                    std::array<std::uint8_t, 8> payload{};
                    ++sequence;
                    for (std::size_t i = 0; i < payload.size(); ++i)
                    {
                        payload[payload.size() - 1 - i] =
                            static_cast<std::uint8_t>(sequence >> (8U * i));
                    }
                    Client->SendPing(payload);
                    next = std::chrono::steady_clock::now() + PingInterval;
                }
            }
        }
        catch (...)
        {
            if (!stop.stop_requested())
            {
                Logger.LogWarning("DERP wake transport failed: {}", winrt::to_message());
            }
        }
    }
};

DerpWakeTransport::~DerpWakeTransport()
{
    Close();
}

void DerpWakeTransport::Prepare()
{
    Close();
    auto state = std::make_shared<State>();
    std::lock_guard lock(m_stateMutex);
    m_state = std::move(state);
}

std::shared_ptr<DerpWakeTransport::State> DerpWakeTransport::GetState() const
{
    std::lock_guard lock(m_stateMutex);
    return m_state;
}

sockets::StreamSocket DerpWakeTransport::Socket() const
{
    const auto state = GetState();
    return state ? state->Socket : nullptr;
}

void DerpWakeTransport::Connect(const std::string& host, std::stop_token cancellation)
{
    const auto state = GetState();
    if (!state || host.empty())
    {
        throw winrt::hresult_invalid_argument();
    }
    const std::stop_callback cancelled(cancellation,
                                       [state]
                                       {
                                           state->Cancellation.request_stop();
                                       });
    const auto stop = state->Cancellation.get_token();
    const winrt::Windows::Networking::HostName name(winrt::to_hstring(host));
    std::string_view stage = "TCP connect";
    try
    {
        AwaitOperation(
            state->Socket.ConnectAsync(name, L"443", sockets::SocketProtectionLevel::PlainSocket),
            IoTimeout,
            stop);
        stage = "TLS upgrade";
        AwaitOperation(state->Socket.UpgradeToSslAsync(sockets::SocketProtectionLevel::Tls12, name),
                       IoTimeout,
                       stop);
        stage = "DERP authentication";
        state->Io = std::make_unique<UwpStreamIo>(
            state->Socket.InputStream(),
            state->Socket.OutputStream(),
            StreamIoOptions{.Timeout = IoTimeout, .Cancellation = stop});
        state->Stream = std::make_unique<VpnCallbackStream>(*state->Io);
        const auto privateKey = crypto::GeneratePrivateKey();
        state->Client = std::make_unique<derp::DerpClient>(
            *state->Stream, privateKey, crypto::X25519PublicFromPrivate(privateKey));
        state->Client->Connect(host, stop);
        state->Stream->UseCallbackInput();
    }
    catch (...)
    {
        state->Logger.LogError("{} failed: {}", stage, winrt::to_message());
        throw;
    }
}

void DerpWakeTransport::Start()
{
    const auto state = GetState();
    if (!state || !state->Client || state->Worker.joinable())
    {
        throw winrt::hresult_illegal_method_call();
    }
    state->Worker = std::jthread(
        [state](std::stop_token stop)
        {
            state->Run(stop);
        });
}

void DerpWakeTransport::Receive(std::span<const std::uint8_t> bytes)
{
    const auto state = GetState();
    if (!state)
    {
        return;
    }
    std::lock_guard lock(state->Mutex);
    if (state->Closed || !state->Stream)
    {
        return;
    }
    if (!state->Stream->AppendInput(bytes))
    {
        state->Logger.LogWarning("DERP receive queue limit exceeded");
        state->Closed = true;
    }
    state->Ready.notify_all();
}

void DerpWakeTransport::Close() noexcept
{
    std::shared_ptr<State> state;
    {
        std::lock_guard lock(m_stateMutex);
        state = std::exchange(m_state, {});
    }
    if (!state)
    {
        return;
    }
    {
        std::lock_guard lock(state->Mutex);
        state->Closed = true;
    }
    state->Worker.request_stop();
    state->Cancellation.request_stop();
    state->Ready.notify_all();
    if (state->Worker.joinable())
    {
        state->Worker.join();
    }
    try
    {
        state->Socket.Close();
    }
    catch (...)
    { /* Windows may already have closed the associated socket. */
    }
}

} // namespace tailgate::uwp::bg
