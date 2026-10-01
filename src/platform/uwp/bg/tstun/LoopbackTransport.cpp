#include "LoopbackTransport.h"

#include <chrono>
#include <mutex>
#include <system_error>
#include <thread>
#include <utility>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Networking.h>
#include <winrt/Windows.Storage.Streams.h>

#include <tailgate/base/Logger.h>

#include "common/EventLoop.h"
#include "common/ThreadApartment.h"
#include "common/UwpFireAndForget.h"
#include "common/WinrtOperation.h"

namespace tailgate::uwp::bg
{
namespace sockets = winrt::Windows::Networking::Sockets;
namespace streams = winrt::Windows::Storage::Streams;

struct LoopbackTransport::State
{
    State(std::shared_ptr<base::EventLoop> events, base::TimeProvider& time)
        : Events(std::move(events)), Time(time)
    {
    }

    static FireAndForget Send(std::shared_ptr<State> state)
    {
        co_await winrt::resume_background();
        try
        {
            for (;;)
            {
                streams::IOutputStream output{nullptr};
                {
                    std::lock_guard lock(state->Mutex);
                    if (state->Closed || !std::exchange(state->Pending, false))
                    {
                        state->Writing = false;
                        co_return;
                    }
                    output = state->Output;
                }
                streams::Buffer packet(1);
                packet.data()[0] = 0;
                packet.Length(1);
                if (co_await output.WriteAsync(packet) != 1)
                {
                    throw std::system_error(std::make_error_code(std::errc::io_error));
                }
            }
        }
        catch (...)
        {
            std::lock_guard lock(state->Mutex);
            state->Writing = false;
            if (!state->Closed)
            {
                state->Failed = true;
                state->Logger.LogWarning("VPN callback wake failed: {}", winrt::to_message());
                state->Events->Wake();
            }
        }
    }

    static void Wake(const std::shared_ptr<State>& state)
    {
        {
            std::lock_guard lock(state->Mutex);
            if (state->Closed || state->Failed)
            {
                return;
            }
            state->Pending = true;
            if (std::exchange(state->Writing, true))
            {
                return;
            }
        }
        Send(state);
    }

    static void Pulse(const std::shared_ptr<State>& state, std::stop_token stop)
    {
        try
        {
            ThreadApartment::Ensure();
            constexpr auto PulseInterval = std::chrono::seconds(1);
            while (!stop.stop_requested())
            {
                const auto deadline = state->Time.After(PulseInterval);
                (void)state->PulseEvents.Wait(*deadline, 1);
                if (!stop.stop_requested())
                {
                    Wake(state);
                }
            }
        }
        catch (...)
        {
            std::lock_guard lock(state->Mutex);
            if (!state->Closed)
            {
                state->Failed = true;
                state->Logger.LogWarning("VPN callback pulse failed: {}", winrt::to_message());
                state->Events->Wake();
            }
        }
    }

    std::mutex Mutex;
    std::shared_ptr<base::EventLoop> Events;
    base::TimeProvider& Time;
    tailgate::uwp::EventLoop PulseEvents;
    std::jthread PulseThread;
    sockets::DatagramSocket Transport;
    sockets::DatagramSocket Local;
    streams::IOutputStream Output{nullptr};
    bool Pending = false;
    bool Writing = false;
    bool Closed = false;
    bool Failed = false;
    base::Logger Logger{"vpn-loopback"};
};

LoopbackTransport::LoopbackTransport(std::shared_ptr<base::EventLoop> events,
                                     base::TimeProvider& time)
    : m_events(std::move(events)), m_time(time)
{
}

LoopbackTransport::~LoopbackTransport()
{
    Close();
}

void LoopbackTransport::Open(const winrt::Windows::Networking::Vpn::VpnChannel& channel,
                             std::stop_token cancellation)
{
    if (m_state)
    {
        throw winrt::hresult_illegal_method_call();
    }
    auto state = std::make_shared<State>(m_events, m_time);
    m_state = state;
    constexpr auto SetupTimeout = std::chrono::seconds(10);
    const winrt::Windows::Networking::HostName loopback(L"127.0.0.1");
    try
    {
        // The local peer consumes outgoing keepalives; incoming callback wakes are
        // sent explicitly, so an idle channel never needs an external echo server.
        state->Local.MessageReceived(
            [](const auto&, const auto&)
            {
            });
        AwaitOperation(state->Local.BindEndpointAsync(loopback, L"0"), SetupTimeout, cancellation);
        channel.AssociateTransport(state->Transport, nullptr);
        AwaitOperation(
            state->Transport.ConnectAsync(loopback, state->Local.Information().LocalPort()),
            SetupTimeout,
            cancellation);
        state->Output = AwaitOperation(
            state->Local.GetOutputStreamAsync(loopback, state->Transport.Information().LocalPort()),
            SetupTimeout,
            cancellation);
    }
    catch (...)
    {
        Close();
        throw;
    }
}

sockets::DatagramSocket LoopbackTransport::Socket() const
{
    return m_state ? m_state->Transport : nullptr;
}

void LoopbackTransport::StartPulsing()
{
    const auto state = m_state;
    if (!state || state->PulseThread.joinable())
    {
        throw winrt::hresult_illegal_method_call();
    }
    // Bootstrap callback delivery before the startup dispatch completes. Later pulses
    // use the same coalesced writer as normal packet delivery and never carry IP data.
    State::Wake(state);
    state->PulseThread = std::jthread(
        [state](std::stop_token stop)
        {
            State::Pulse(state, stop);
        });
}

void LoopbackTransport::Wake()
{
    if (const auto state = m_state)
    {
        State::Wake(state);
    }
}

bool LoopbackTransport::Failed() const
{
    if (!m_state)
    {
        return false;
    }
    std::lock_guard lock(m_state->Mutex);
    return m_state->Failed;
}

void LoopbackTransport::Close() noexcept
{
    const auto state = std::exchange(m_state, {});
    if (!state)
    {
        return;
    }
    {
        std::lock_guard lock(state->Mutex);
        state->Closed = true;
    }
    state->PulseThread.request_stop();
    state->PulseEvents.Wake();
    if (state->PulseThread.joinable())
    {
        state->PulseThread.join();
    }
    try
    {
        state->Transport.Close();
    }
    catch (...)
    {
        // Windows may already have closed its transport while stopping the channel.
    }
    try
    {
        state->Local.Close();
    }
    catch (...)
    {
        // Socket shutdown must remain safe after cancellation or a failed setup.
    }
}

} // namespace tailgate::uwp::bg
