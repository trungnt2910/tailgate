#pragma once

#include <algorithm>
#include <cstdint>
#include <vector>

#include <winrt/Windows.Networking.Vpn.h>
#include <winrt/Windows.Storage.Streams.h>

namespace tailgate::uwp::tests
{

class FakeVpnPacketBuffer
    : public winrt::implements<FakeVpnPacketBuffer,
                               winrt::Windows::Networking::Vpn::IVpnPacketBuffer>
{
public:
    explicit FakeVpnPacketBuffer(const std::vector<std::uint8_t>& bytes)
        : m_buffer(static_cast<std::uint32_t>(bytes.size()))
    {
        std::ranges::copy(bytes, m_buffer.data());
        m_buffer.Length(static_cast<std::uint32_t>(bytes.size()));
    }

    auto Buffer() const
    {
        return m_buffer;
    }

    auto Status() const
    {
        return m_status;
    }

    void Status(winrt::Windows::Networking::Vpn::VpnPacketBufferStatus value)
    {
        m_status = value;
    }

    auto TransportAffinity() const
    {
        return m_affinity;
    }

    void TransportAffinity(std::uint32_t value)
    {
        m_affinity = value;
    }

private:
    winrt::Windows::Storage::Streams::Buffer m_buffer;
    winrt::Windows::Networking::Vpn::VpnPacketBufferStatus m_status{};
    std::uint32_t m_affinity = 0;
};

} // namespace tailgate::uwp::tests
