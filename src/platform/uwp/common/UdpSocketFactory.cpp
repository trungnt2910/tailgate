#include "UdpSocketFactory.h"

#include <algorithm>
#include <deque>
#include <map>
#include <mutex>
#include <utility>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Networking.h>
#include <winrt/Windows.Storage.Streams.h>

#include <tailgate/base/Logger.h>

#include "NetworkAdapter.h"
#include "ThreadApartment.h"
#include "UwpFireAndForget.h"

namespace tailgate::uwp
{
namespace
{

namespace foundation = winrt::Windows::Foundation;
namespace sockets = winrt::Windows::Networking::Sockets;
namespace streams = winrt::Windows::Storage::Streams;
using types::nettype::SocketIoResult;
using types::nettype::UdpDatagram;
constexpr std::size_t MaximumIpv4Payload = 65507;
constexpr std::size_t MaximumPackets = 256;
constexpr std::size_t MaximumBytes = 4 * 1024 * 1024;
constexpr std::size_t MaximumOutputStreams = 64;

struct PendingDatagram
{
    net::Endpoint Destination;
    std::vector<std::uint8_t> Payload;
};

struct DatagramState final
{
    DatagramState(std::shared_ptr<base::EventLoop> events, base::EventToken token)
        : Events(std::move(events)), Token(token)
    {
    }

    void Notify(base::EventReadiness readiness)
    {
        // Called under Mutex, including from completions: Close disables notifications
        // before cancelling operations, so retired callbacks cannot wake the old owner.
        if (!Closed)
        {
            Events->Post({.Token = Token, .Readiness = readiness});
        }
    }

    void Track(const foundation::IAsyncInfo& operation)
    {
        std::lock_guard lock(Mutex);
        if (Closed)
        {
            operation.Cancel();
        }
        else
        {
            Operation = operation;
        }
    }

    static FireAndForget Bind(std::shared_ptr<DatagramState> state,
                              types::nettype::UdpSocketOptions options)
    {
        co_await winrt::resume_background();
        try
        {
            const auto adapter = NetworkAdapter(options.NetworkInterface).Native();
            const auto service = winrt::to_hstring(options.BindEndpoint.Port());
            foundation::IAsyncAction operation{nullptr};
            if (adapter)
            {
                if (options.BindEndpoint.Address().HostOrder() != 0)
                {
                    throw winrt::hresult_not_implemented();
                }
                operation = state->Socket.BindServiceNameAsync(service, adapter);
            }
            else if (options.BindEndpoint.Address().HostOrder() != 0)
            {
                operation = state->Socket.BindEndpointAsync(
                    winrt::Windows::Networking::HostName(
                        winrt::to_hstring(options.BindEndpoint.Address().ToString())),
                    service);
            }
            else
            {
                operation = state->Socket.BindServiceNameAsync(service);
            }
            state->Track(operation);
            co_await operation;
            const auto info = state->Socket.Information();
            const auto local = info.LocalAddress();
            const auto address =
                local ? net::Ipv4Address::TryParse(winrt::to_string(local.CanonicalName()))
                      : std::nullopt;
            const auto endpoint =
                net::Endpoint::TryParse(address.value_or(net::Ipv4Address{}).ToString() + ":" +
                                        winrt::to_string(info.LocalPort()));
            std::lock_guard lock(state->Mutex);
            if (state->Closed)
            {
                co_return;
            }
            state->Operation = nullptr;
            state->Ready = true;
            state->Local = endpoint.value_or(net::Endpoint{});
            state->Notify(base::EventReadiness::Writable);
        }
        catch (...)
        {
            std::lock_guard lock(state->Mutex);
            if (!state->Closed)
            {
                state->Failed = true;
                state->Log.LogWarning("UDP bind failed: {}", winrt::to_message());
                state->Notify(base::EventReadiness::Error);
            }
        }
    }

    static FireAndForget Send(std::shared_ptr<DatagramState> state)
    {
        co_await winrt::resume_background();
        for (;;)
        {
            PendingDatagram packet;
            {
                std::lock_guard lock(state->Mutex);
                if (state->Closed || state->Output.empty())
                {
                    state->Sending = false;
                    co_return;
                }
                packet = state->Output.front();
            }
            try
            {
                const auto key = packet.Destination.ToString();
                auto found = state->Streams.find(key);
                streams::IOutputStream output{nullptr};
                if (found != state->Streams.end())
                {
                    output = found->second;
                }
                else
                {
                    auto operation = state->Socket.GetOutputStreamAsync(
                        winrt::Windows::Networking::HostName(
                            winrt::to_hstring(packet.Destination.Address().ToString())),
                        winrt::to_hstring(packet.Destination.Port()));
                    state->Track(operation);
                    output = co_await operation;
                    if (state->Streams.size() >= MaximumOutputStreams)
                    {
                        state->Streams.erase(state->Streams.begin());
                    }
                    state->Streams.emplace(key, output);
                }
                streams::Buffer buffer(static_cast<std::uint32_t>(packet.Payload.size()));
                std::copy(packet.Payload.begin(), packet.Payload.end(), buffer.data());
                buffer.Length(static_cast<std::uint32_t>(packet.Payload.size()));
                auto operation = output.WriteAsync(buffer);
                state->Track(operation);
                const auto written = co_await operation;
                if (written != packet.Payload.size())
                {
                    state->Log.LogWarning("UDP write was incomplete");
                }
            }
            catch (...)
            {
                std::lock_guard lock(state->Mutex);
                if (!state->Closed)
                {
                    // UDP delivery can fail per destination. Other peers keep their socket.
                    state->Log.LogWarning("UDP send failed: {}", winrt::to_message());
                    state->Streams.erase(packet.Destination.ToString());
                }
            }
            std::lock_guard lock(state->Mutex);
            if (!state->Closed)
            {
                state->Operation = nullptr;
                state->OutputBytes -= state->Output.front().Payload.size();
                state->Output.pop_front();
                if (state->WriteInterest)
                {
                    state->Notify(base::EventReadiness::Writable);
                }
            }
        }
    }

    void Receive(const sockets::DatagramSocketMessageReceivedEventArgs& args)
    {
        try
        {
            const auto source =
                net::Endpoint::TryParse(winrt::to_string(args.RemoteAddress().CanonicalName()) +
                                        ":" + winrt::to_string(args.RemotePort()));
            if (!source)
            {
                return;
            }
            const auto reader = args.GetDataReader();
            std::vector<std::uint8_t> payload(reader.UnconsumedBufferLength());
            reader.ReadBytes(payload);
            std::lock_guard lock(Mutex);
            if (Closed || Input.size() >= MaximumPackets ||
                InputBytes + payload.size() > MaximumBytes)
            {
                return;
            }
            InputBytes += payload.size();
            Input.push_back(UdpDatagram{.Source = *source, .Payload = std::move(payload)});
            Notify(base::EventReadiness::Readable);
        }
        catch (...)
        {
            Log.LogWarning("UDP receive failed: {}", winrt::to_message());
        }
    }

    std::mutex Mutex;
    std::shared_ptr<base::EventLoop> Events;
    base::EventToken Token;
    sockets::DatagramSocket Socket;
    winrt::event_token ReceivedToken{};
    foundation::IAsyncInfo Operation{nullptr};
    std::map<std::string, streams::IOutputStream> Streams;
    std::deque<UdpDatagram> Input;
    std::deque<PendingDatagram> Output;
    std::size_t InputBytes = 0;
    std::size_t OutputBytes = 0;
    net::Endpoint Local;
    bool Ready = false;
    bool Failed = false;
    bool Closed = false;
    bool Sending = false;
    bool WriteInterest = false;
    base::Logger Log{"uwp-udp"};
};

class UdpSocket final : public types::nettype::UdpSocket
{
public:
    UdpSocket(std::shared_ptr<base::EventLoop> events,
              const types::nettype::UdpSocketOptions& options)
        : m_state(std::make_shared<DatagramState>(std::move(events), options.ReadinessToken))
    {
        m_state->ReceivedToken = m_state->Socket.MessageReceived(
            [weak = std::weak_ptr(m_state)](const auto&, const auto& args)
            {
                if (const auto state = weak.lock())
                {
                    state->Receive(args);
                }
            });
        DatagramState::Bind(m_state, options);
    }

    ~UdpSocket() override
    {
        Close();
    }

    SocketIoResult TrySendTo(const net::Endpoint& destination,
                             const std::vector<std::uint8_t>& payload) override
    {
        bool start = false;
        {
            std::lock_guard lock(m_state->Mutex);
            if (m_state->Closed)
            {
                return SocketIoResult::Closed;
            }
            if (m_state->Failed || payload.size() > MaximumIpv4Payload)
            {
                return SocketIoResult::Unavailable;
            }
            if (!m_state->Ready || m_state->Output.size() >= MaximumPackets ||
                m_state->OutputBytes + payload.size() > MaximumBytes)
            {
                return SocketIoResult::WouldBlock;
            }
            m_state->OutputBytes += payload.size();
            m_state->Output.push_back(
                PendingDatagram{.Destination = destination, .Payload = payload});
            start = !std::exchange(m_state->Sending, true);
        }
        if (start)
        {
            DatagramState::Send(m_state);
        }
        return SocketIoResult::Complete;
    }

    types::nettype::UdpReceiveResult TryReceive(std::size_t maximumSize) override
    {
        std::lock_guard lock(m_state->Mutex);
        if (m_state->Closed)
        {
            return {.Result = SocketIoResult::Closed, .Datagram = {}};
        }
        if (m_state->Input.empty())
        {
            return {};
        }
        auto packet = std::move(m_state->Input.front());
        m_state->Input.pop_front();
        m_state->InputBytes -= packet.Payload.size();
        if (!m_state->Input.empty())
        {
            m_state->Notify(base::EventReadiness::Readable);
        }
        if (packet.Payload.size() > maximumSize)
        {
            m_state->Log.LogWarning("UDP datagram exceeds receive capacity");
            return {};
        }
        return {.Result = SocketIoResult::Complete, .Datagram = std::move(packet)};
    }

    net::Endpoint LocalEndpoint() const override
    {
        std::lock_guard lock(m_state->Mutex);
        return m_state->Local;
    }

    void SetWriteInterest(bool enabled) override
    {
        std::lock_guard lock(m_state->Mutex);
        const bool previous = std::exchange(m_state->WriteInterest, enabled);
        if (enabled && !previous && m_state->Ready && m_state->Output.size() < MaximumPackets &&
            m_state->OutputBytes < MaximumBytes)
        {
            m_state->Notify(base::EventReadiness::Writable);
        }
    }

    void Close() noexcept override
    {
        foundation::IAsyncInfo operation{nullptr};
        {
            std::lock_guard lock(m_state->Mutex);
            if (std::exchange(m_state->Closed, true))
            {
                return;
            }
            operation = std::exchange(m_state->Operation, nullptr);
            m_state->Input.clear();
            m_state->Output.clear();
            m_state->InputBytes = m_state->OutputBytes = 0;
            m_state->Events->DiscardPostedEvents(m_state->Token);
        }
        try
        {
            m_state->Socket.MessageReceived(m_state->ReceivedToken);
        }
        catch (...)
        { /* Socket closure still runs if event removal fails. */
        }
        try
        {
            if (operation)
            {
                operation.Cancel();
            }
        }
        catch (...)
        { /* A completed operation can reject cancellation. Still close the socket. */
        }
        try
        {
            m_state->Socket.Close();
        }
        catch (...)
        { /* Late completions observe Closed and release their owned state. */
        }
    }

private:
    std::shared_ptr<DatagramState> m_state;
};

} // namespace

UdpSocketFactory::UdpSocketFactory(std::shared_ptr<base::EventLoop> events)
    : m_events(std::move(events))
{
}

std::unique_ptr<types::nettype::UdpSocket>
UdpSocketFactory::OpenUdpSocket(const types::nettype::UdpSocketOptions& options)
{
    ThreadApartment::Ensure();
    return std::make_unique<UdpSocket>(m_events, options);
}

} // namespace tailgate::uwp
