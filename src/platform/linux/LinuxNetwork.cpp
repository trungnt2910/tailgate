#include "LinuxNetwork.h"

#include "tailgate/network/ResolverConfig.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <vector>

#include <arpa/inet.h>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace tailgate::linux_frontend
{
namespace
{

std::optional<unsigned int> ParseHexUnsigned(std::string text)
{
    if (text.empty() || text.size() > sizeof(unsigned int) * 2)
    {
        return std::nullopt;
    }
    if (text.size() % 2 != 0)
    {
        text.insert(text.begin(), '0');
    }
    std::vector<std::uint8_t> bytes;
    try
    {
        boost::algorithm::unhex(text, std::back_inserter(bytes));
    }
    catch (const boost::algorithm::hex_decode_error&)
    {
        return std::nullopt;
    }
    unsigned int result = 0;
    for (const std::uint8_t byte : bytes)
    {
        result = (result << 8U) | byte;
    }
    return result;
}

} // namespace

UniqueFd OpenTun(const std::string& name)
{
    UniqueFd fd(open("/dev/net/tun", O_RDWR | O_NONBLOCK));
    if (fd.Fd < 0)
    {
        throw std::runtime_error("failed to open /dev/net/tun: " +
                                 std::string(std::strerror(errno)));
    }
    ifreq request{};
    request.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(request.ifr_name, name.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd.Fd, TUNSETIFF, &request) != 0)
    {
        throw std::runtime_error("TUNSETIFF failed: " + std::string(std::strerror(errno)));
    }
    return fd;
}

void SetInterfaceAddress(const std::string& name, const std::string& address)
{
    UniqueFd fd(socket(AF_INET, SOCK_DGRAM, 0));
    if (fd.Fd < 0)
    {
        throw std::runtime_error("failed to open interface configuration socket");
    }
    ifreq request{};
    std::strncpy(request.ifr_name, name.c_str(), IFNAMSIZ - 1);
    sockaddr_in interfaceAddress{};
    interfaceAddress.sin_family = AF_INET;
    if (inet_pton(AF_INET, address.c_str(), &interfaceAddress.sin_addr) != 1)
    {
        throw std::runtime_error("invalid interface address: " + address);
    }
    std::memcpy(&request.ifr_addr, &interfaceAddress, sizeof(interfaceAddress));
    if (ioctl(fd.Fd, SIOCSIFADDR, &request) != 0)
    {
        throw std::runtime_error("SIOCSIFADDR failed: " + std::string(std::strerror(errno)));
    }
    sockaddr_in mask{};
    mask.sin_family = AF_INET;
    mask.sin_addr.s_addr = htonl(0xffffffffU);
    std::memcpy(&request.ifr_netmask, &mask, sizeof(mask));
    if (ioctl(fd.Fd, SIOCSIFNETMASK, &request) != 0 || ioctl(fd.Fd, SIOCGIFFLAGS, &request) != 0)
    {
        throw std::runtime_error("failed to configure interface: " +
                                 std::string(std::strerror(errno)));
    }
    request.ifr_flags = static_cast<short>(request.ifr_flags | IFF_UP | IFF_RUNNING);
    if (ioctl(fd.Fd, SIOCSIFFLAGS, &request) != 0)
    {
        throw std::runtime_error("SIOCSIFFLAGS failed: " + std::string(std::strerror(errno)));
    }
}

void SetInterfaceIpv6Address(const std::string& name, const std::string& address)
{
    UniqueFd fd(socket(AF_INET6, SOCK_DGRAM, 0));
    if (fd.Fd < 0)
    {
        throw std::runtime_error("failed to open IPv6 interface configuration socket");
    }
    ifreq request{};
    std::strncpy(request.ifr_name, name.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd.Fd, SIOCGIFINDEX, &request) != 0)
    {
        throw std::runtime_error("SIOCGIFINDEX failed: " + std::string(std::strerror(errno)));
    }
    in6_ifreq ipv6{};
    if (inet_pton(AF_INET6, address.c_str(), &ipv6.ifr6_addr) != 1)
    {
        throw std::runtime_error("invalid IPv6 interface address: " + address);
    }
    ipv6.ifr6_prefixlen = 48;
    ipv6.ifr6_ifindex = request.ifr_ifindex;
    if (ioctl(fd.Fd, SIOCSIFADDR, &ipv6) != 0 && errno != EEXIST)
    {
        throw std::runtime_error("IPv6 SIOCSIFADDR failed: " + std::string(std::strerror(errno)));
    }
}

void SetInterfaceMtu(const std::string& name, int mtu)
{
    UniqueFd fd(socket(AF_INET, SOCK_DGRAM, 0));
    if (fd.Fd < 0)
    {
        throw std::runtime_error("failed to open interface configuration socket");
    }
    ifreq request{};
    std::strncpy(request.ifr_name, name.c_str(), IFNAMSIZ - 1);
    request.ifr_mtu = mtu;
    if (ioctl(fd.Fd, SIOCSIFMTU, &request) != 0)
    {
        throw std::runtime_error("SIOCSIFMTU failed: " + std::string(std::strerror(errno)));
    }
}

void AddRoute(const std::string& interfaceName, const network::Ipv4Prefix& prefix)
{
    UniqueFd fd(socket(AF_INET, SOCK_DGRAM, 0));
    if (fd.Fd < 0)
    {
        throw std::runtime_error("failed to open route socket");
    }
    rtentry route{};
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_addr.s_addr = htonl(prefix.Network);
    sockaddr_in mask{};
    mask.sin_family = AF_INET;
    mask.sin_addr.s_addr = htonl(network::PrefixMask(prefix.PrefixLength));
    std::memcpy(&route.rt_dst, &destination, sizeof(destination));
    std::memcpy(&route.rt_genmask, &mask, sizeof(mask));
    route.rt_flags = RTF_UP;
    route.rt_dev = const_cast<char*>(interfaceName.c_str());
    if (ioctl(fd.Fd, SIOCADDRT, &route) != 0 && errno != EEXIST)
    {
        throw std::runtime_error("SIOCADDRT failed: " + std::string(std::strerror(errno)));
    }
}

void RemoveRoute(const std::string& interfaceName, const network::Ipv4Prefix& prefix)
{
    UniqueFd fd(socket(AF_INET, SOCK_DGRAM, 0));
    if (fd.Fd < 0)
    {
        throw std::runtime_error("failed to open route socket");
    }
    rtentry route{};
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_addr.s_addr = htonl(prefix.Network);
    sockaddr_in mask{};
    mask.sin_family = AF_INET;
    mask.sin_addr.s_addr = htonl(network::PrefixMask(prefix.PrefixLength));
    std::memcpy(&route.rt_dst, &destination, sizeof(destination));
    std::memcpy(&route.rt_genmask, &mask, sizeof(mask));
    route.rt_flags = RTF_UP;
    route.rt_dev = const_cast<char*>(interfaceName.c_str());
    if (ioctl(fd.Fd, SIOCDELRT, &route) != 0 && errno != ESRCH && errno != ENOENT)
    {
        throw std::runtime_error("SIOCDELRT failed: " + std::string(std::strerror(errno)));
    }
}

void WriteResolver(const std::string& dnsResolver, const std::vector<std::string>& domains)
{
    std::ifstream input("/etc/resolv.conf", std::ios::binary);
    if (!input)
    {
        throw std::runtime_error("failed to read /etc/resolv.conf");
    }
    const std::string contents{std::istreambuf_iterator<char>(input),
                               std::istreambuf_iterator<char>()};
    std::ofstream resolv("/etc/resolv.conf", std::ios::binary | std::ios::trunc);
    if (!resolv)
    {
        throw std::runtime_error("failed to write /etc/resolv.conf");
    }
    resolv << network::ApplyResolverSection(contents, dnsResolver, domains);
}

std::vector<std::string> ReadResolverAddresses()
{
    std::ifstream resolv("/etc/resolv.conf", std::ios::binary);
    const std::string contents{std::istreambuf_iterator<char>(resolv),
                               std::istreambuf_iterator<char>()};
    return network::ResolverAddresses(contents);
}

UniqueFd OpenUdpSocket()
{
    return OpenUdpSocket({});
}

UniqueFd OpenUdpSocket(const std::string& interfaceName)
{
    constexpr int transportBufferBytes = 4 * 1024 * 1024;
    UniqueFd fd(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    if (fd.Fd >= 0)
    {
        (void)setsockopt(
            fd.Fd, SOL_SOCKET, SO_RCVBUF, &transportBufferBytes, sizeof(transportBufferBytes));
        (void)setsockopt(
            fd.Fd, SOL_SOCKET, SO_SNDBUF, &transportBufferBytes, sizeof(transportBufferBytes));
        const int flags = fcntl(fd.Fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd.Fd, F_SETFL, flags | O_NONBLOCK) != 0)
        {
            throw std::runtime_error("failed to configure UDP nonblocking mode: " +
                                     std::string(std::strerror(errno)));
        }
    }
    if (fd.Fd >= 0 && !interfaceName.empty() &&
        setsockopt(
            fd.Fd, SOL_SOCKET, SO_BINDTODEVICE, interfaceName.c_str(), interfaceName.size() + 1) !=
            0)
    {
        throw std::runtime_error("failed to bind UDP transport to " + interfaceName + ": " +
                                 std::string(std::strerror(errno)));
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (fd.Fd < 0 || bind(fd.Fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0)
    {
        throw std::runtime_error("failed to open UDP socket: " + std::string(std::strerror(errno)));
    }
    return fd;
}

std::string DefaultRouteInterface()
{
    std::ifstream routes("/proc/net/route");
    std::string line;
    std::getline(routes, line);
    while (std::getline(routes, line))
    {
        std::vector<std::string> fields;
        boost::algorithm::split(
            fields, line, boost::algorithm::is_any_of(" \t"), boost::algorithm::token_compress_on);
        fields.erase(std::remove(fields.begin(), fields.end(), std::string{}), fields.end());
        const std::optional<unsigned int> flags =
            fields.size() >= 4 ? ParseHexUnsigned(fields[3]) : std::nullopt;
        if (flags && fields[1] == "00000000" && (*flags & RTF_UP) != 0)
        {
            return fields[0];
        }
    }
    throw std::runtime_error("failed to identify the default-route interface");
}

std::uint32_t InterfaceIpv4Address(const std::string& interfaceName)
{
    UniqueFd fd(socket(AF_INET, SOCK_DGRAM, 0));
    ifreq request{};
    std::strncpy(request.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);
    if (fd.Fd < 0 || ioctl(fd.Fd, SIOCGIFADDR, &request) != 0)
    {
        throw std::runtime_error("failed to read IPv4 address for " + interfaceName + ": " +
                                 std::string(std::strerror(errno)));
    }
    const auto* address = reinterpret_cast<const sockaddr_in*>(&request.ifr_addr);
    return ntohl(address->sin_addr.s_addr);
}

std::uint16_t SocketPort(int fd)
{
    sockaddr_in address{};
    socklen_t size = sizeof(address);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) != 0)
    {
        throw std::runtime_error("failed to read UDP socket address: " +
                                 std::string(std::strerror(errno)));
    }
    return ntohs(address.sin_port);
}

UniqueFd OpenLocalDnsSocket()
{
    UniqueFd fd(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    int reuse = 1;
    setsockopt(fd.Fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    const int flags = fcntl(fd.Fd, F_GETFL, 0);
    if (fd.Fd < 0 || flags < 0 || fcntl(fd.Fd, F_SETFL, flags | O_NONBLOCK) != 0)
    {
        throw std::runtime_error("failed to configure local DNS socket: " +
                                 std::string(std::strerror(errno)));
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(53);
    if (fd.Fd < 0 || bind(fd.Fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0)
    {
        throw std::runtime_error("failed to bind local DNS proxy: " +
                                 std::string(std::strerror(errno)));
    }
    return fd;
}

bool TrySendUdp(int fd, const sockaddr_in& endpoint, const std::vector<std::uint8_t>& data)
{
    const ssize_t sent = sendto(fd,
                                data.data(),
                                data.size(),
                                MSG_DONTWAIT,
                                reinterpret_cast<const sockaddr*>(&endpoint),
                                sizeof(endpoint));
    if (sent == static_cast<ssize_t>(data.size()))
    {
        return true;
    }
    if (sent >= 0)
    {
        throw std::runtime_error("UDP send was truncated");
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)
    {
        return false;
    }
    throw std::runtime_error("UDP send failed: " + std::string(std::strerror(errno)));
}

void SendUdp(int fd, const sockaddr_in& endpoint, const std::vector<std::uint8_t>& data)
{
    (void)TrySendUdp(fd, endpoint, data);
}

std::optional<sockaddr_in> TryParseIpv4Endpoint(const std::string& endpoint)
{
    const std::size_t colon = endpoint.rfind(':');
    sockaddr_in address{};
    address.sin_family = AF_INET;
    if (colon == std::string::npos ||
        inet_pton(AF_INET, endpoint.substr(0, colon).c_str(), &address.sin_addr) != 1)
    {
        return std::nullopt;
    }
    const std::string portText = endpoint.substr(colon + 1);
    char* portEnd = nullptr;
    const unsigned long port = std::strtoul(portText.c_str(), &portEnd, 10);
    if (portText.empty() || portEnd == nullptr || *portEnd != '\0' || port > 65535)
    {
        return std::nullopt;
    }
    address.sin_port = htons(static_cast<std::uint16_t>(port));
    return address;
}

sockaddr_in ParseIpv4Endpoint(const std::string& endpoint)
{
    const std::optional<sockaddr_in> address = TryParseIpv4Endpoint(endpoint);
    if (!address)
    {
        throw std::runtime_error("invalid IPv4 endpoint: " + endpoint);
    }
    return *address;
}

std::vector<std::uint8_t> ReceiveUdp(int fd, sockaddr_in* source)
{
    std::vector<std::uint8_t> data(4096);
    socklen_t length = sizeof(*source);
    const ssize_t received = recvfrom(
        fd, data.data(), data.size(), MSG_DONTWAIT, reinterpret_cast<sockaddr*>(source), &length);
    if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
        return {};
    }
    if (received < 0)
    {
        throw std::runtime_error("UDP receive failed: " + std::string(std::strerror(errno)));
    }
    data.resize(static_cast<std::size_t>(received));
    return data;
}

void WriteAll(int fd, const std::vector<std::uint8_t>& data)
{
    std::size_t offset = 0;
    while (offset < data.size())
    {
        const ssize_t written = write(fd, data.data() + offset, data.size() - offset);
        if (written < 0)
        {
            throw std::runtime_error("write failed: " + std::string(std::strerror(errno)));
        }
        offset += static_cast<std::size_t>(written);
    }
}

} // namespace tailgate::linux_frontend
