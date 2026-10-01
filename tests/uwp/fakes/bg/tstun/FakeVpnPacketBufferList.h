#pragma once

#include <cstdint>
#include <deque>

#include <winrt/Windows.Networking.Vpn.h>

namespace tailgate::uwp::tests
{

class FakeVpnPacketBufferList
    : public winrt::implements<FakeVpnPacketBufferList,
                               winrt::Windows::Networking::Vpn::IVpnPacketBufferList>
{
public:
    using Packet = winrt::Windows::Networking::Vpn::VpnPacketBuffer;

    void Append(const Packet& packet)
    {
        m_packets.push_back(packet);
    }

    void AddAtBegin(const Packet& packet)
    {
        m_packets.push_front(packet);
    }

    Packet RemoveAtBegin()
    {
        auto packet = m_packets.front();
        m_packets.pop_front();
        return packet;
    }

    Packet RemoveAtEnd()
    {
        auto packet = m_packets.back();
        m_packets.pop_back();
        return packet;
    }

    void Clear()
    {
        m_packets.clear();
    }

    std::uint32_t Size() const
    {
        return static_cast<std::uint32_t>(m_packets.size());
    }

    auto Status() const
    {
        return m_status;
    }

    void Status(winrt::Windows::Networking::Vpn::VpnPacketBufferStatus value)
    {
        m_status = value;
    }

private:
    std::deque<Packet> m_packets;
    winrt::Windows::Networking::Vpn::VpnPacketBufferStatus m_status{};
};

} // namespace tailgate::uwp::tests
