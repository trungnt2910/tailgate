#pragma once

#include <cstdint>
#include <vector>

#include <winrt/Windows.Networking.Vpn.h>

namespace tailgate::uwp::bg
{

class VpnPacketBufferReader final
{
public:
    // Return every consumed Windows buffer through the send list. The associated
    // loopback receiver ignores its one-byte payload; protocol traffic uses owned bytes.
    [[nodiscard]] static std::vector<std::uint8_t>
    Read(const winrt::Windows::Networking::Vpn::VpnPacketBufferList& input,
         const winrt::Windows::Networking::Vpn::VpnPacketBufferList& output);
};

} // namespace tailgate::uwp::bg
