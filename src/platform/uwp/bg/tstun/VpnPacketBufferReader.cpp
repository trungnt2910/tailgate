#include "VpnPacketBufferReader.h"

#include <winrt/Windows.Storage.Streams.h>

namespace tailgate::uwp::bg
{
namespace
{

void PrepareLoopbackSend(const winrt::Windows::Storage::Streams::Buffer& buffer)
{
    // A zero-length send does not reliably return buffers on RS2. This datagram is
    // consumed by the local socket and contains no original host-packet contents.
    buffer.Length(1);
    buffer.data()[0] = 0;
}

} // namespace

std::vector<std::uint8_t>
VpnPacketBufferReader::Read(const winrt::Windows::Networking::Vpn::VpnPacketBufferList& input,
                            const winrt::Windows::Networking::Vpn::VpnPacketBufferList& output)
{
    const auto packet = input.RemoveAtBegin();
    // Transfer ownership before allocation, just as when filling a receive buffer.
    output.Append(packet);
    const auto buffer = packet.Buffer();
    std::vector<std::uint8_t> result;
    try
    {
        result.assign(buffer.data(), buffer.data() + buffer.Length());
    }
    catch (...)
    {
        PrepareLoopbackSend(buffer);
        throw;
    }
    PrepareLoopbackSend(buffer);
    return result;
}

} // namespace tailgate::uwp::bg
