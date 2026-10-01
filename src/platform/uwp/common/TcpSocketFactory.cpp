#include "TcpSocketFactory.h"

#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

#include "ThreadApartment.h"
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
    if (options.Cancellation.stop_requested())
    {
        throw std::system_error(std::make_error_code(std::errc::operation_canceled));
    }
    try
    {
        ThreadApartment::Ensure();
        auto transport = std::make_unique<UwpTcpStream>(sockets::StreamSocket(), options);
        if (options.NonBlockingAfterConnect)
        {
            transport->SetNonBlocking(true);
        }
        return transport;
    }
    catch (const winrt::hresult_error& error)
    {
        throw std::system_error(error.code().value, std::system_category());
    }
}

} // namespace tailgate::uwp
