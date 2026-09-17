#include <cerrno>
#include <cstring>

#include <netinet/in.h>
#include <sys/socket.h>

#include <gtest/gtest.h>

#include "impl/TcpPortReservationFactory.h"

#include "UniqueFd.h"

namespace tailgate::tests
{

class Given_LinuxTcpPortReservation : public testing::TestWithParam<bool>
{
};

TEST_P(Given_LinuxTcpPortReservation,
       When_LeaseIsHeldThenReleased_Then_HostBindIsExcludedUntilRelease)
{
    linux_frontend::impl::TcpPortReservationFactory factory;
    const bool ipv6 = GetParam();
    const auto local = net::IpAddress::Parse(ipv6 ? "::1" : "127.0.0.1");
    auto lease = factory.TryReserve(local);
    ASSERT_NE(lease, nullptr);
    ASSERT_NE(lease->Port(), 0);
    linux_frontend::UniqueFd competitor(
        socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP));
    ASSERT_GE(competitor.Fd, 0);
    sockaddr_storage storage{};
    socklen_t size = 0;
    if (ipv6)
    {
        auto& address = reinterpret_cast<sockaddr_in6&>(storage);
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(lease->Port());
        std::memcpy(&address.sin6_addr, local.Bytes().data(), local.Bytes().size());
        size = sizeof(address);
    }
    else
    {
        auto& address = reinterpret_cast<sockaddr_in&>(storage);
        address.sin_family = AF_INET;
        address.sin_port = htons(lease->Port());
        std::memcpy(&address.sin_addr, local.Bytes().data(), local.Bytes().size());
        size = sizeof(address);
    }

    const auto heldResult = bind(competitor.Fd, reinterpret_cast<sockaddr*>(&storage), size);
    const auto heldError = errno;
    lease.reset();
    const auto releasedResult = bind(competitor.Fd, reinterpret_cast<sockaddr*>(&storage), size);

    EXPECT_EQ(heldResult, -1);
    EXPECT_EQ(heldError, EADDRINUSE);
    EXPECT_EQ(releasedResult, 0);
}

INSTANTIATE_TEST_SUITE_P(AddressFamilies, Given_LinuxTcpPortReservation, testing::Bool());

TEST(Given_LinuxTcpPortReservationFactory, When_AddressIsUnspecified_Then_ReservationIsRefused)
{
    linux_frontend::impl::TcpPortReservationFactory factory;

    const auto lease = factory.TryReserve(net::IpAddress{});

    EXPECT_EQ(lease, nullptr);
}

} // namespace tailgate::tests
