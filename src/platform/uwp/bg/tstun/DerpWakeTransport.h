#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <stop_token>
#include <string>

#include <winrt/Windows.Networking.Sockets.h>

namespace tailgate::uwp::bg
{

// Associated TCP wake transport. This independent DERP identity carries
// only protocol Ping/Pong traffic; the Core retains its normal peer transports.
class DerpWakeTransport final
{
public:
    ~DerpWakeTransport();
    void Prepare();
    [[nodiscard]] winrt::Windows::Networking::Sockets::StreamSocket Socket() const;
    void Connect(const std::string& host, std::stop_token cancellation);
    void Start();
    void Receive(std::span<const std::uint8_t> bytes);
    void Close() noexcept;

private:
    struct State;
    [[nodiscard]] std::shared_ptr<State> GetState() const;
    mutable std::mutex m_stateMutex;
    std::shared_ptr<State> m_state;
};

} // namespace tailgate::uwp::bg
