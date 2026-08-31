#pragma once

#include <memory>

#include <tailgate/types/nettype/UdpSocket.h>

#include "event/EventRegistry.h"

namespace tailgate::linux_frontend::impl
{

class UdpSocketFactory final : public tailgate::types::nettype::UdpSocketFactory
{
public:
    explicit UdpSocketFactory(
        std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> eventRegistry);

    [[nodiscard]] std::unique_ptr<tailgate::types::nettype::UdpSocket>
    OpenUdpSocket(const tailgate::types::nettype::UdpSocketOptions& options) override;

private:
    std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> m_eventRegistry;
};

} // namespace tailgate::linux_frontend::impl
