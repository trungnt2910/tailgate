#pragma once

#include <memory>
#include <stop_token>

#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Networking.Vpn.h>

#include <tailgate/base/EventLoop.h>

namespace tailgate::uwp::bg
{

// The optional associated UDP transport. Its datagrams only request receive callbacks;
// application-owned sockets carry all relay/DERP/peer traffic.
class LoopbackTransport final
{
public:
    LoopbackTransport(std::shared_ptr<base::EventLoop> events, base::TimeProvider& time);
    ~LoopbackTransport();
    void Open(const winrt::Windows::Networking::Vpn::VpnChannel& channel,
              const winrt::Windows::Networking::Sockets::StreamSocket& mainTransport,
              std::stop_token cancellation);
    [[nodiscard]] winrt::Windows::Networking::Sockets::DatagramSocket Socket() const;
    void StartPulsing();
    void Wake();
    [[nodiscard]] bool Failed() const;
    void Close() noexcept;

private:
    struct State;
    std::shared_ptr<base::EventLoop> m_events;
    base::TimeProvider& m_time;
    std::shared_ptr<State> m_state;
};

} // namespace tailgate::uwp::bg
