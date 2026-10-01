#pragma once

#include <tailgate/net/netmon/Resolver.h>
#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::uwp
{

class UnderlayResolver final : public tailgate::net::netmon::Resolver
{
public:
    explicit UnderlayResolver(tailgate::types::nettype::TcpSocketFactory& sockets);
    [[nodiscard]] tailgate::net::Endpoint
    Resolve(const std::string& host,
            std::uint16_t port,
            const std::optional<std::string>& networkInterface,
            std::stop_token cancellation) override;

private:
    tailgate::types::nettype::TcpSocketFactory& m_sockets;
};

} // namespace tailgate::uwp
