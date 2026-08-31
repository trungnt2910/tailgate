#pragma once

#include <memory>

#include <tailgate/types/nettype/TcpSocket.h>
#include <tailgate/wgengine/tstun/Device.h>

#include "PacketDescriptorProvider.h"
#include "UniqueFd.h"

#include "event/EventRegistry.h"

namespace tailgate::linux_frontend::impl
{

class TunDevice final : public tailgate::wgengine::tstun::Device
{
public:
    TunDevice(std::shared_ptr<PacketDescriptorProvider> descriptorProvider,
              std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> eventRegistry,
              tailgate::types::nettype::TcpSocketFactory& socketFactory);
    ~TunDevice() override;

    [[nodiscard]] bool Open(const tailgate::wgengine::tstun::DeviceOptions& options) override;
    [[nodiscard]] tailgate::wgengine::tstun::DeviceReadResult
    TryRead(std::size_t maximumPacketSize) override;
    [[nodiscard]] tailgate::wgengine::tstun::DeviceIoResult
    TryWrite(const std::vector<std::uint8_t>& packet) override;
    void SetWriteInterest(bool enabled) override;
    void Close() noexcept override;
    [[nodiscard]] std::unique_ptr<tailgate::types::nettype::TcpSocket>
    OpenTransportSocket(const tailgate::types::nettype::TcpSocketOptions& options) override;

private:
    std::shared_ptr<PacketDescriptorProvider> m_descriptorProvider;
    std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> m_eventRegistry;
    tailgate::types::nettype::TcpSocketFactory& m_socketFactory;
    UniqueFd m_descriptor;
    tailgate::linux_frontend::event::EventHandle m_eventHandle;
    bool m_writeInterest = false;
};

} // namespace tailgate::linux_frontend::impl
