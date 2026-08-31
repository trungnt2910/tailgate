#pragma once

#include <memory>

#include <tailgate/types/nettype/TcpSocket.h>

#include "event/EventRegistry.h"

namespace tailgate::linux_frontend::impl
{

class TcpSocketFactory final : public tailgate::types::nettype::TcpSocketFactory
{
public:
    explicit TcpSocketFactory(
        std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> eventRegistry);

    [[nodiscard]] std::unique_ptr<tailgate::types::nettype::TcpSocket>
    OpenTcpSocket(const tailgate::types::nettype::TcpSocketOptions& options) override;

private:
    std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> m_eventRegistry;
};

} // namespace tailgate::linux_frontend::impl
