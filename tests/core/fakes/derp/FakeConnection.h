#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include <tailgate/base/EventLoop.h>
#include <tailgate/derp/Connection.h>

namespace tailgate::tests::fakes::derp
{

class FakeConnection final : public tailgate::derp::Connection
{
public:
    struct SentPacket
    {
        tailgate::derp::DerpClient::Key Destination{};
        std::vector<std::uint8_t> Payload;
        tailgate::derp::DerpSendQueue::Priority Priority =
            tailgate::derp::DerpSendQueue::Priority::Data;
    };

    FakeConnection(tailgate::base::EventToken token, tailgate::derp::DerpClient::Packet packet)
        : m_token(token), m_packet(std::move(packet))
    {
    }

    void Send(const tailgate::derp::DerpClient::Key& destination,
              std::vector<std::uint8_t> payload,
              tailgate::derp::DerpSendQueue::Priority priority) override
    {
        Sent.push_back(SentPacket{
            .Destination = destination,
            .Payload = std::move(payload),
            .Priority = priority,
        });
    }

    tailgate::derp::ConnectionEventResult ProcessEvent(const tailgate::base::Event& event) override
    {
        if (event.Token != m_token)
        {
            return {};
        }
        return tailgate::derp::ConnectionEventResult{
            .Handled = true,
            .Status = tailgate::derp::ConnectionEventStatus::Ready,
            .Packets = {std::move(m_packet)},
        };
    }

    void Maintain() override
    {
        ++MaintenanceCalls;
    }

    bool Connected() const noexcept override
    {
        return true;
    }

    std::size_t MaintenanceCalls = 0;
    std::vector<SentPacket> Sent;

private:
    tailgate::base::EventToken m_token;
    tailgate::derp::DerpClient::Packet m_packet;
};

} // namespace tailgate::tests::fakes::derp
