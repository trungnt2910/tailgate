#include <array>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <stop_token>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/netmap/NetworkMap.h>

#include "UniqueFd.h"
#include "impl/CancellableWait.h"
#include "impl/TcpStream.h"

namespace
{

using tailgate::linux_frontend::UniqueFd;
constexpr char UnderlayName[] = "test-underlay";
constexpr auto ServerAddress = tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 1);
constexpr auto LoopbackAddress = tailgate::net::Ipv4Address::FromOctets(127, 0, 0, 1);
constexpr auto TestTimeout = std::chrono::seconds(3);
constexpr std::size_t MaximumDnsQuerySize = 4096;

enum class DnsFixtureError
{
    InvalidReply,
};

class ResolverFile final
{
public:
    ResolverFile()
        : Path(std::filesystem::temp_directory_path() /
               std::format("tailgate-dns-test-{}", getpid()))
    {
        std::ofstream file(Path);
        file.exceptions(std::ios::failbit | std::ios::badbit);
        file << "nameserver 127.0.0.1\n";
    }

    ~ResolverFile()
    {
        std::error_code ignored;
        std::filesystem::remove(Path, ignored);
    }

    const std::filesystem::path Path;
};

void WriteMapping(const char* path, const std::string& contents)
{
    std::ofstream file(path);
    file.exceptions(std::ios::failbit | std::ios::badbit);
    file << contents;
}

// Executed in a fresh GTest subprocess before any resolver threads exist. Network and
// mount changes disappear with this process and never affect the host or other tests.
void CheckLoopbackResolution()
{
    const auto uid = getuid();
    const auto gid = getgid();
    ASSERT_EQ(unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS), 0) << std::strerror(errno);
    WriteMapping("/proc/self/setgroups", "deny");
    WriteMapping("/proc/self/uid_map", std::format("0 {} 1", uid));
    WriteMapping("/proc/self/gid_map", std::format("0 {} 1", gid));
    ASSERT_EQ(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr), 0);
    const ResolverFile resolver;
    ASSERT_EQ(mount(resolver.Path.c_str(), "/etc/resolv.conf", nullptr, MS_BIND, nullptr), 0);
    UniqueFd configuration(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    ASSERT_GE(configuration.Fd, 0);
    ifreq loopback{};
    std::strcpy(loopback.ifr_name, "lo");
    loopback.ifr_flags = IFF_UP;
    ASSERT_EQ(ioctl(configuration.Fd, SIOCSIFFLAGS, &loopback), 0);
    UniqueFd tun(open("/dev/net/tun", O_RDWR | O_CLOEXEC));
    ASSERT_GE(tun.Fd, 0);
    ifreq underlay{};
    std::strcpy(underlay.ifr_name, UnderlayName);
    underlay.ifr_flags = IFF_TUN | IFF_NO_PI;
    ASSERT_EQ(ioctl(tun.Fd, TUNSETIFF, &underlay), 0);
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_addr.s_addr = htonl(ServerAddress.HostOrder());
    std::memcpy(&underlay.ifr_addr, &destination, sizeof(destination));
    ASSERT_EQ(ioctl(configuration.Fd, SIOCSIFADDR, &underlay), 0);
    underlay.ifr_flags = IFF_UP;
    ASSERT_EQ(ioctl(configuration.Fd, SIOCSIFFLAGS, &underlay), 0);
    UniqueFd listener(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    ASSERT_GE(listener.Fd, 0);
    ASSERT_EQ(
        bind(listener.Fd, reinterpret_cast<const sockaddr*>(&destination), sizeof(destination)), 0);
    ASSERT_EQ(listen(listener.Fd, 1), 0);
    socklen_t length = sizeof(destination);
    ASSERT_EQ(getsockname(listener.Fd, reinterpret_cast<sockaddr*>(&destination), &length), 0);
    UniqueFd dns(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    ASSERT_GE(dns.Fd, 0);
    sockaddr_in resolverAddress{};
    resolverAddress.sin_family = AF_INET;
    resolverAddress.sin_addr.s_addr = htonl(LoopbackAddress.HostOrder());
    resolverAddress.sin_port = htons(tailgate::net::dns::DnsPort);
    ASSERT_EQ(
        bind(dns.Fd, reinterpret_cast<const sockaddr*>(&resolverAddress), sizeof(resolverAddress)),
        0);
    tailgate::types::netmap::NetworkConfig network;
    network.SelfName("server.example.ts.net.");
    network.SelfAddress("192.0.2.1");
    network.SelfAddresses({"192.0.2.1"});
    network.MagicDnsDomain("example.ts.net");
    std::exception_ptr dnsError;
    std::size_t replies = 0;
    std::jthread dnsWorker(
        [&](std::stop_token stop)
        {
            try
            {
                for (;;)
                {
                    tailgate::linux_frontend::impl::WaitForSocket(
                        dns.Fd, POLLIN, TestTimeout, stop);
                    std::vector<std::uint8_t> query(MaximumDnsQuerySize);
                    sockaddr_in client{};
                    socklen_t clientLength = sizeof(client);
                    const auto received = recvfrom(dns.Fd,
                                                   query.data(),
                                                   query.size(),
                                                   0,
                                                   reinterpret_cast<sockaddr*>(&client),
                                                   &clientLength);
                    if (received < 0)
                    {
                        throw std::system_error(errno, std::generic_category());
                    }
                    query.resize(static_cast<std::size_t>(received));
                    const auto packet = tailgate::net::packet::Ipv4UdpDatagram::Build(
                        ntohl(client.sin_addr.s_addr),
                        tailgate::net::dns::MagicDnsIpv4Address,
                        ntohs(client.sin_port),
                        tailgate::net::dns::DnsPort,
                        query);
                    const auto response =
                        tailgate::net::dns::TailnetDnsResponse::Build(network, packet);
                    if (!response)
                    {
                        throw DnsFixtureError::InvalidReply;
                    }
                    const auto datagram = tailgate::net::packet::Ipv4UdpDatagram::Parse(*response);
                    if (!datagram)
                    {
                        throw DnsFixtureError::InvalidReply;
                    }
                    const auto& payload = datagram->Payload();
                    if (sendto(dns.Fd,
                               payload.data(),
                               payload.size(),
                               0,
                               reinterpret_cast<const sockaddr*>(&client),
                               clientLength) < 0)
                    {
                        throw std::system_error(errno, std::generic_category());
                    }
                    ++replies;
                }
            }
            catch (const std::system_error& error)
            {
                if (error.code() != std::errc::operation_canceled)
                {
                    dnsError = std::current_exception();
                }
            }
            catch (...)
            {
                dnsError = std::current_exception();
            }
        });
    std::string boundDevice;
    std::exception_ptr connectError;

    try
    {
        tailgate::linux_frontend::impl::TcpStream stream(
            "server.example.ts.net",
            std::to_string(ntohs(destination.sin_port)),
            UnderlayName,
            static_cast<int>(TestTimeout.count()));
        std::array<char, IFNAMSIZ> device{};
        socklen_t deviceLength = device.size();
        if (getsockopt(
                stream.NativeHandle(), SOL_SOCKET, SO_BINDTODEVICE, device.data(), &deviceLength) !=
            0)
        {
            throw std::system_error(errno, std::generic_category());
        }
        boundDevice = device.data();
    }
    catch (...)
    {
        connectError = std::current_exception();
    }
    dnsWorker.request_stop();
    dnsWorker.join();

    std::cerr << std::format("DNS replies: {}; TCP device: {}\n", replies, boundDevice);
    if (connectError)
    {
        try
        {
            std::rethrow_exception(connectError);
        }
        catch (const std::exception& error)
        {
            std::cerr << std::format("TCP connection failed: {}\n", error.what());
        }
    }

    EXPECT_EQ(connectError, nullptr);
    EXPECT_EQ(dnsError, nullptr);
    EXPECT_GT(replies, 0U);
    EXPECT_EQ(boundDevice, UnderlayName);
}

} // namespace

TEST(Given_LinuxTcpResolutionDeathTest,
     When_TcpUsesAnotherInterface_Then_LoopbackDnsResolvesAndTcpRetainsBinding)
{
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    const auto scenario = []
    {
        CheckLoopbackResolution();
        std::exit(::testing::Test::HasFailure() ? EXIT_FAILURE : EXIT_SUCCESS);
    };

    EXPECT_EXIT(scenario(), ::testing::ExitedWithCode(EXIT_SUCCESS), "");
}
