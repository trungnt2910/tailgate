#pragma once

#include <tailgate/net/http/Client.h>
#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::net::http::impl
{

class ClientImpl final : public Client
{
public:
    explicit ClientImpl(tailgate::types::nettype::TcpSocketFactory& socketFactory) noexcept;

    [[nodiscard]] Response Send(const Request& request) override;

private:
    tailgate::types::nettype::TcpSocketFactory& m_socketFactory;
};

} // namespace tailgate::net::http::impl
