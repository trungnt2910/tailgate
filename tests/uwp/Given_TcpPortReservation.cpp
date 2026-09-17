#include <cstring>
#include <memory>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <gtest/gtest.h>

#include "common/TcpPortReservationFactory.h"

namespace tailgate::uwp::tests
{
namespace
{

class BindProbe final
{
public:
    explicit BindProbe(bool ipv6)
    {
        WSADATA data{};
        m_started = WSAStartup(MAKEWORD(2, 2), &data) == 0;
        if (m_started)
        {
            m_socket = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
        }
    }

    ~BindProbe()
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

    bool Valid() const
    {
        return m_socket != INVALID_SOCKET;
    }

    int Bind(const net::IpAddress& local, std::uint16_t port)
    {
        sockaddr_storage storage{};
        int size = 0;
        if (local.Family() == net::AddressFamily::Ipv6)
        {
            auto& address = reinterpret_cast<sockaddr_in6&>(storage);
            address.sin6_family = AF_INET6;
            address.sin6_port = htons(port);
            std::memcpy(&address.sin6_addr, local.Bytes().data(), sizeof(address.sin6_addr));
            size = sizeof(address);
        }
        else
        {
            auto& address = reinterpret_cast<sockaddr_in&>(storage);
            address.sin_family = AF_INET;
            address.sin_port = htons(port);
            std::memcpy(&address.sin_addr, local.Bytes().data(), sizeof(address.sin_addr));
            size = sizeof(address);
        }
        return bind(m_socket, reinterpret_cast<sockaddr*>(&storage), size);
    }

private:
    SOCKET m_socket = INVALID_SOCKET;
    bool m_started = false;
};

} // namespace

class Given_UwpTcpPortReservation : public testing::TestWithParam<bool>
{
};

TEST_P(Given_UwpTcpPortReservation,
       When_FactoryDiesWhileLeaseIsHeld_Then_EndpointRemainsExcludedUntilRelease)
{
    auto factory = std::make_unique<TcpPortReservationFactory>();
    const auto local = net::IpAddress::Parse(GetParam() ? "::1" : "127.0.0.1");
    auto lease = factory->TryReserve(local);
    ASSERT_NE(lease, nullptr);
    const auto port = lease->Port();
    ASSERT_NE(port, 0);
    BindProbe competitor(GetParam());
    ASSERT_TRUE(competitor.Valid());

    factory.reset();
    const auto held = competitor.Bind(local, port);
    const auto error = WSAGetLastError();
    lease.reset();
    const auto released = competitor.Bind(local, port);

    EXPECT_EQ(held, SOCKET_ERROR);
    EXPECT_TRUE(error == WSAEADDRINUSE || error == WSAEACCES);
    EXPECT_EQ(released, 0);
}

INSTANTIATE_TEST_SUITE_P(AddressFamilies, Given_UwpTcpPortReservation, testing::Bool());

TEST(Given_UwpTcpPortReservationFactory, When_AddressIsUnspecified_Then_NoSocketIsReserved)
{
    TcpPortReservationFactory factory;

    const auto lease = factory.TryReserve(net::IpAddress{});

    EXPECT_EQ(lease, nullptr);
}

} // namespace tailgate::uwp::tests
