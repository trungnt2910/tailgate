#include "TunDevice.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <system_error>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

#include <tailgate/wgengine/tstun/Device.h>

namespace tailgate::linux_frontend::impl
{

TunDevice::TunDevice(std::shared_ptr<PacketDescriptorProvider> descriptorProvider,
                     std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> eventRegistry,
                     tailgate::types::nettype::TcpSocketFactory& socketFactory)
    : m_descriptorProvider(std::move(descriptorProvider)),
      m_eventRegistry(std::move(eventRegistry)),
      m_socketFactory(socketFactory)
{
}

TunDevice::~TunDevice()
{
    Close();
}

bool TunDevice::Open(const tailgate::wgengine::tstun::DeviceOptions& options)
{
    if (m_descriptor.Fd >= 0 || options.ReadinessToken.Value == 0)
    {
        return false;
    }
    m_descriptor = m_descriptorProvider->Open(options.Name);
    const int flags = fcntl(m_descriptor.Fd, F_GETFL, 0);
    if (flags < 0 || fcntl(m_descriptor.Fd, F_SETFL, flags | O_NONBLOCK) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    m_eventHandle =
        m_eventRegistry->Register(m_descriptor.Fd,
                                  tailgate::linux_frontend::event::EventInterest::Readable,
                                  options.ReadinessToken);
    return true;
}

tailgate::wgengine::tstun::DeviceReadResult TunDevice::TryRead(std::size_t maximumPacketSize)
{
    std::vector<std::uint8_t> packet(maximumPacketSize);
    const ssize_t size = read(m_descriptor.Fd, packet.data(), packet.size());
    if (size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
        return {};
    }
    if (size < 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    if (size == 0)
    {
        return tailgate::wgengine::tstun::DeviceReadResult{
            .Result = tailgate::wgengine::tstun::DeviceIoResult::Closed,
            .Packet = {},
        };
    }
    packet.resize(static_cast<std::size_t>(size));
    return tailgate::wgengine::tstun::DeviceReadResult{
        .Result = tailgate::wgengine::tstun::DeviceIoResult::Complete,
        .Packet = std::move(packet),
    };
}

tailgate::wgengine::tstun::DeviceIoResult
TunDevice::TryWrite(const std::vector<std::uint8_t>& packet)
{
    const ssize_t size = write(m_descriptor.Fd, packet.data(), packet.size());
    if (size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
        return tailgate::wgengine::tstun::DeviceIoResult::WouldBlock;
    }
    if (size < 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    if (size == 0)
    {
        return tailgate::wgengine::tstun::DeviceIoResult::Closed;
    }
    if (static_cast<std::size_t>(size) != packet.size())
    {
        throw std::system_error(std::make_error_code(std::errc::io_error));
    }
    return tailgate::wgengine::tstun::DeviceIoResult::Complete;
}

void TunDevice::SetWriteInterest(bool enabled)
{
    if (m_descriptor.Fd < 0 || m_writeInterest == enabled)
    {
        return;
    }
    const tailgate::linux_frontend::event::EventInterest interest =
        enabled ? tailgate::linux_frontend::event::EventInterest::Readable |
                      tailgate::linux_frontend::event::EventInterest::Writable
                : tailgate::linux_frontend::event::EventInterest::Readable;
    m_eventHandle.Modify(interest);
    m_writeInterest = enabled;
}

void TunDevice::Close() noexcept
{
    m_eventHandle.Reset();
    m_descriptor.Reset();
    m_writeInterest = false;
}

std::unique_ptr<tailgate::types::nettype::TcpSocket>
TunDevice::OpenTransportSocket(const tailgate::types::nettype::TcpSocketOptions& options)
{
    return m_socketFactory.OpenTcpSocket(options);
}

} // namespace tailgate::linux_frontend::impl
