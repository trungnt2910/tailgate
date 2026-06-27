#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace tailgate::protocol
{

class IPacketSink
{
public:
    virtual ~IPacketSink() = default;

    [[nodiscard]] virtual bool TrySendPacket(const std::vector<std::uint8_t>& packet) = 0;
    void SendPacket(const std::vector<std::uint8_t>& packet)
    {
        if (!TrySendPacket(packet))
        {
            throw std::runtime_error("packet sink would block");
        }
    }
};

class IPacketSource
{
public:
    virtual ~IPacketSource() = default;

    [[nodiscard]] virtual std::optional<std::vector<std::uint8_t>> TryReceivePacket() = 0;
    [[nodiscard]] std::vector<std::uint8_t> ReceivePacket()
    {
        std::optional<std::vector<std::uint8_t>> packet = TryReceivePacket();
        if (!packet)
        {
            throw std::runtime_error("packet source would block");
        }
        return std::move(*packet);
    }
};

} // namespace tailgate::protocol
