#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

#include <tailgate/net/Endpoint.h>
#include <tailgate/types/nettype/UdpSocket.h>

namespace tailgate::tests::fakes
{

struct SentUdpDatagram
{
    tailgate::net::Endpoint Destination;
    std::vector<std::uint8_t> Payload;
};

struct FakeUdpSocketState
{
    tailgate::net::Endpoint LocalEndpoint;
    std::deque<tailgate::types::nettype::UdpReceiveResult> Incoming;
    std::vector<SentUdpDatagram> Sent;
    tailgate::types::nettype::SocketIoResult SendResult =
        tailgate::types::nettype::SocketIoResult::Complete;
    std::function<void(const tailgate::net::Endpoint&, const std::vector<std::uint8_t>&)> OnSend;
    bool Closed = false;
    bool WriteInterest = false;
};

class FakeUdpSocket final : public tailgate::types::nettype::UdpSocket
{
public:
    explicit FakeUdpSocket(std::shared_ptr<FakeUdpSocketState> state) : m_state(std::move(state))
    {
    }

    tailgate::types::nettype::SocketIoResult
    TrySendTo(const tailgate::net::Endpoint& destination,
              const std::vector<std::uint8_t>& payload) override
    {
        if (m_state->Closed)
        {
            return tailgate::types::nettype::SocketIoResult::Closed;
        }
        if (m_state->SendResult == tailgate::types::nettype::SocketIoResult::Complete)
        {
            m_state->Sent.push_back(SentUdpDatagram{
                .Destination = destination,
                .Payload = payload,
            });
            if (m_state->OnSend)
            {
                m_state->OnSend(destination, payload);
            }
        }
        return m_state->SendResult;
    }

    tailgate::types::nettype::UdpReceiveResult TryReceive(std::size_t) override
    {
        if (m_state->Closed)
        {
            return tailgate::types::nettype::UdpReceiveResult{
                .Result = tailgate::types::nettype::SocketIoResult::Closed,
                .Datagram = {},
            };
        }
        if (m_state->Incoming.empty())
        {
            return {};
        }
        tailgate::types::nettype::UdpReceiveResult result = std::move(m_state->Incoming.front());
        m_state->Incoming.pop_front();
        return result;
    }

    tailgate::net::Endpoint LocalEndpoint() const override
    {
        return m_state->LocalEndpoint;
    }

    void SetWriteInterest(bool enabled) override
    {
        m_state->WriteInterest = enabled;
    }

    void Close() noexcept override
    {
        m_state->Closed = true;
    }

private:
    std::shared_ptr<FakeUdpSocketState> m_state;
};

class FakeUdpSocketFactory final : public tailgate::types::nettype::UdpSocketFactory
{
public:
    std::unique_ptr<tailgate::types::nettype::UdpSocket>
    OpenUdpSocket(const tailgate::types::nettype::UdpSocketOptions& options) override
    {
        Options.push_back(options);
        auto state = std::make_shared<FakeUdpSocketState>();
        state->LocalEndpoint = options.BindEndpoint;
        if (state->LocalEndpoint.Port() == 0)
        {
            state->LocalEndpoint = tailgate::net::Endpoint(
                state->LocalEndpoint.Address(),
                static_cast<std::uint16_t>(FirstEphemeralPort + States.size()));
        }
        States.push_back(state);
        return std::make_unique<FakeUdpSocket>(std::move(state));
    }

    static constexpr std::uint16_t FirstEphemeralPort = 40000;

    std::vector<tailgate::types::nettype::UdpSocketOptions> Options;
    std::vector<std::shared_ptr<FakeUdpSocketState>> States;
};

} // namespace tailgate::tests::fakes
