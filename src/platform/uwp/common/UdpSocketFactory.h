#pragma once

#include <memory>

#include <tailgate/base/EventLoop.h>
#include <tailgate/types/nettype/UdpSocket.h>

namespace tailgate::uwp
{

class UdpSocketFactory final : public types::nettype::UdpSocketFactory
{
public:
    explicit UdpSocketFactory(std::shared_ptr<base::EventLoop> events);
    [[nodiscard]] std::unique_ptr<types::nettype::UdpSocket>
    OpenUdpSocket(const types::nettype::UdpSocketOptions& options) override;

private:
    std::shared_ptr<base::EventLoop> m_events;
};

} // namespace tailgate::uwp
