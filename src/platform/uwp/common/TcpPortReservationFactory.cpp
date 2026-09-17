#include "TcpPortReservationFactory.h"

#include <cstring>

#include <winsock2.h>
#include <ws2tcpip.h>

namespace tailgate::uwp
{
namespace
{

class Reservation final : public types::nettype::TcpPortReservation
{
public:
    ~Reservation() override
    {
        if (m_socket != INVALID_SOCKET)
        {
            (void)closesocket(m_socket);
        }
        if (m_started)
        {
            (void)WSACleanup();
        }
    }

    bool TryOpen(const net::IpAddress& localAddress)
    {
        WSADATA data{};
        constexpr WORD WinsockVersion = MAKEWORD(2, 2);
        if (WSAStartup(WinsockVersion, &data) != 0)
        {
            return false;
        }
        // Each lease owns its Winsock reference, so it may outlive its DI factory.
        m_started = true;
        const bool ipv6 = localAddress.Family() == net::AddressFamily::Ipv6;
        m_socket = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_socket == INVALID_SOCKET)
        {
            return false;
        }
        const DWORD enabled = 1;
        if (setsockopt(m_socket,
                       SOL_SOCKET,
                       SO_EXCLUSIVEADDRUSE,
                       reinterpret_cast<const char*>(&enabled),
                       sizeof(enabled)) != 0 ||
            (ipv6 && setsockopt(m_socket,
                                IPPROTO_IPV6,
                                IPV6_V6ONLY,
                                reinterpret_cast<const char*>(&enabled),
                                sizeof(enabled)) != 0))
        {
            return false;
        }
        sockaddr_storage storage{};
        int size = 0;
        if (ipv6)
        {
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
        // Port zero asks Windows to exclude an ephemeral endpoint from its allocator.
        // The socket never connects or listens; all TCP traffic belongs to Core's stack.
        if (bind(m_socket, reinterpret_cast<sockaddr*>(&storage), size) != 0 ||
            getsockname(m_socket, reinterpret_cast<sockaddr*>(&storage), &size) != 0)
        {
            return false;
        }
        m_port = ntohs(ipv6 ? reinterpret_cast<const sockaddr_in6&>(storage).sin6_port
                            : reinterpret_cast<const sockaddr_in&>(storage).sin_port);
        return m_port != 0;
    }

    std::uint16_t Port() const noexcept override
    {
        return m_port;
    }

private:
    SOCKET m_socket = INVALID_SOCKET;
    std::uint16_t m_port = 0;
    bool m_started = false;
};

} // namespace

std::unique_ptr<types::nettype::TcpPortReservation>
TcpPortReservationFactory::TryReserve(const net::IpAddress& localAddress)
{
    if (localAddress.IsUnspecified())
    {
        return nullptr;
    }
    auto reservation = std::make_unique<Reservation>();
    if (!reservation->TryOpen(localAddress))
    {
        return nullptr;
    }
    return reservation;
}

} // namespace tailgate::uwp
