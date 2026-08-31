#include "TcpSocketFactory.h"

#include <stdexcept>
#include <string>
#include <utility>

#include "UwpTcpStream.h"

namespace tailgate::uwp
{
namespace
{

namespace sockets = winrt::Windows::Networking::Sockets;

} // namespace

std::unique_ptr<tailgate::types::nettype::TcpSocket>
TcpSocketFactory::OpenTcpSocket(const tailgate::types::nettype::TcpSocketOptions& options)
{
    return ConnectTcpSocket(sockets::StreamSocket(), options);
}

std::unique_ptr<tailgate::types::nettype::TcpSocket>
TcpSocketFactory::ConnectTcpSocket(sockets::StreamSocket socket,
                                   const tailgate::types::nettype::TcpSocketOptions& options)
{
    if (options.NetworkInterface && !options.NetworkInterface->empty())
    {
        throw std::invalid_argument("UWP does not support binding a TCP socket by interface.");
    }
    const sockets::SocketProtectionLevel protection =
        options.TlsServerName ? sockets::SocketProtectionLevel::Tls12
                              : sockets::SocketProtectionLevel::PlainSocket;
    return std::make_unique<UwpTcpStream>(std::move(socket),
                                          options.ConnectAddress,
                                          options.Service,
                                          protection,
                                          options.IoTimeout,
                                          options.TlsServerName.value_or(std::string{}),
                                          options.ConnectTimeout);
}

} // namespace tailgate::uwp
