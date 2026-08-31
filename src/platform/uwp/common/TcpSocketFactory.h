#pragma once

#include <memory>

#include <winrt/Windows.Networking.Sockets.h>

#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::uwp
{

class TcpSocketFactory final : public tailgate::types::nettype::TcpSocketFactory
{
public:
    [[nodiscard]] std::unique_ptr<tailgate::types::nettype::TcpSocket>
    OpenTcpSocket(const tailgate::types::nettype::TcpSocketOptions& options) final;

    [[nodiscard]] static std::unique_ptr<tailgate::types::nettype::TcpSocket>
    ConnectTcpSocket(winrt::Windows::Networking::Sockets::StreamSocket socket,
                     const tailgate::types::nettype::TcpSocketOptions& options);
};

} // namespace tailgate::uwp
