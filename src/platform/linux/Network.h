#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <netinet/in.h>

#include <tailgate/net/Endpoint.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/wgengine/router/Config.h>

#include "UniqueFd.h"

namespace tailgate::linux_frontend
{

enum class AcceptFailureAction
{
    Retry,
    Stop,
};

[[nodiscard]] AcceptFailureAction ClassifyAcceptFailure(int error, bool stopping) noexcept;

void SetInterfaceAddress(const std::string& name, const std::string& address);
void SetInterfaceIpv6Address(const std::string& name, const std::string& address);
void SetInterfaceMtu(const std::string& name, int mtu);
void AddRoute(const std::string& interfaceName, const tailgate::net::packet::Ipv4Prefix& prefix);
void RemoveRoute(const std::string& interfaceName, const tailgate::net::packet::Ipv4Prefix& prefix);
void ApplyRouteChanges(const std::string& interfaceName,
                       const tailgate::wgengine::router::Config& current,
                       const tailgate::wgengine::router::Config& next);
void WriteResolver(const std::string& dnsResolver, const std::vector<std::string>& domains);
[[nodiscard]] std::vector<std::string> ReadResolverAddresses();

[[nodiscard]] UniqueFd OpenUdpSocket();
[[nodiscard]] UniqueFd OpenUdpSocket(const std::string& interfaceName);
[[nodiscard]] std::string DefaultRouteInterface();
[[nodiscard]] std::uint32_t InterfaceIpv4Address(const std::string& interfaceName);
[[nodiscard]] std::uint16_t SocketPort(int fd);
[[nodiscard]] UniqueFd OpenLocalDnsSocket();
[[nodiscard]] bool
TrySendUdp(int fd, const sockaddr_in& endpoint, const std::vector<std::uint8_t>& data);
void SendUdp(int fd, const sockaddr_in& endpoint, const std::vector<std::uint8_t>& data);
[[nodiscard]] std::optional<sockaddr_in> TryParseIpv4Endpoint(const std::string& endpoint);
[[nodiscard]] sockaddr_in ParseIpv4Endpoint(const std::string& endpoint);
[[nodiscard]] tailgate::net::Endpoint ResolveIpv4UdpEndpoint(const std::string& host, int port);
[[nodiscard]] std::vector<std::uint8_t> ReceiveUdp(int fd, sockaddr_in* source);

} // namespace tailgate::linux_frontend
