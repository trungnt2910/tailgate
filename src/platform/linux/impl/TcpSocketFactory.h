#pragma once

#include <memory>

#include <tailgate/types/nettype/TcpSocket.h>

#include "event/EventRegistry.h"

namespace tailgate::linux_frontend::impl
{

class TcpResolver;
class TcpSocketBinder;

class TcpSocketFactory final : public tailgate::types::nettype::TcpSocketFactory
{
public:
    TcpSocketFactory(std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> eventRegistry,
                     TcpResolver& resolver,
                     TcpSocketBinder& binder);

    [[nodiscard]] std::unique_ptr<tailgate::types::nettype::TcpSocket>
    OpenTcpSocket(const tailgate::types::nettype::TcpSocketOptions& options) override;

private:
    std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> m_eventRegistry;
    TcpResolver& m_resolver;
    TcpSocketBinder& m_binder;
};

} // namespace tailgate::linux_frontend::impl
