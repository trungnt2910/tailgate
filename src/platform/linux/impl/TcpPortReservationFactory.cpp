#include "TcpPortReservationFactory.h"

#include <cstring>
#include <utility>

#include <netinet/in.h>
#include <sys/socket.h>

#include "UniqueFd.h"

namespace tailgate::linux_frontend::impl
{
namespace
{

class Reservation final : public types::nettype::TcpPortReservation
{
public:
    Reservation(UniqueFd socket, std::uint16_t port) : m_socket(std::move(socket)), m_port(port)
    {
    }

    std::uint16_t Port() const noexcept override
    {
        return m_port;
    }

private:
    UniqueFd m_socket;
    std::uint16_t m_port;
};

} // namespace

std::unique_ptr<types::nettype::TcpPortReservation>
TcpPortReservationFactory::TryReserve(const net::IpAddress& localAddress)
{
    if (localAddress.IsUnspecified())
    {
        return nullptr;
    }
    const bool ipv6 = localAddress.Family() == net::AddressFamily::Ipv6;
    UniqueFd socket(::socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP));
    if (socket.Fd < 0)
    {
        return nullptr;
    }
    sockaddr_storage storage{};
    socklen_t size = 0;
    if (ipv6)
    {
        const int enabled = 1;
        if (setsockopt(socket.Fd, IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled)) != 0)
        {
            return nullptr;
        }
        auto& address = reinterpret_cast<sockaddr_in6&>(storage);
        address.sin6_family = AF_INET6;
        std::memcpy(&address.sin6_addr, localAddress.Bytes().data(), sizeof(address.sin6_addr));
        size = sizeof(address);
    }
    else
    {
        auto& address = reinterpret_cast<sockaddr_in&>(storage);
        address.sin_family = AF_INET;
        std::memcpy(&address.sin_addr, localAddress.Bytes().data(), sizeof(address.sin_addr));
        size = sizeof(address);
    }
    // No SO_REUSEADDR/PORT: the kernel must exclude this tuple from its allocation.
    if (bind(socket.Fd, reinterpret_cast<sockaddr*>(&storage), size) != 0 ||
        getsockname(socket.Fd, reinterpret_cast<sockaddr*>(&storage), &size) != 0)
    {
        return nullptr;
    }
    const auto port = ntohs(ipv6 ? reinterpret_cast<const sockaddr_in6&>(storage).sin6_port
                                 : reinterpret_cast<const sockaddr_in&>(storage).sin_port);
    return std::make_unique<Reservation>(std::move(socket), port);
}

} // namespace tailgate::linux_frontend::impl
