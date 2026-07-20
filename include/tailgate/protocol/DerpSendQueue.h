#pragma once

#include "tailgate/protocol/Crypto.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <vector>

namespace tailgate::protocol
{

class DerpSendQueue final
{
public:
    enum class Priority
    {
        Data,
        Control,
    };

    struct Packet
    {
        Bytes32 Destination{};
        std::vector<std::uint8_t> Payload;
    };

    struct PushResult
    {
        bool Accepted = false;
        std::size_t DroppedPackets = 0;
    };

    DerpSendQueue(std::size_t maximumPackets, std::size_t maximumBytes);

    [[nodiscard]] PushResult Push(Packet packet, Priority priority);
    [[nodiscard]] std::optional<Packet> Pop();
    [[nodiscard]] std::size_t Size() const;
    [[nodiscard]] std::size_t Bytes() const;

private:
    std::size_t m_maximumPackets;
    std::size_t m_maximumBytes;
    std::size_t m_bytes = 0;
    std::deque<Packet> m_control;
    std::deque<Packet> m_data;
};

} // namespace tailgate::protocol
