#pragma once

#include <memory>

#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::uwp
{

class TcpSocketFactory final : public tailgate::types::nettype::TcpSocketFactory
{
public:
    [[nodiscard]] std::unique_ptr<tailgate::types::nettype::TcpSocket>
    OpenTcpSocket(const tailgate::types::nettype::TcpSocketOptions& options) final;
};

} // namespace tailgate::uwp
