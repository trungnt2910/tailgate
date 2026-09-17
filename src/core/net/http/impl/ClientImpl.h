#pragma once

#include <tailgate/net/http/Client.h>
#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::net::http::impl
{

class ClientImpl final : public Client
{
public:
    ClientImpl(tailgate::types::nettype::TcpSocketFactory& socketFactory,
               MessageParserFactory& parserFactory) noexcept;

    [[nodiscard]] Response Send(const Request& request) override;

private:
    tailgate::types::nettype::TcpSocketFactory& m_socketFactory;
    MessageParserFactory& m_parserFactory;
};

} // namespace tailgate::net::http::impl
