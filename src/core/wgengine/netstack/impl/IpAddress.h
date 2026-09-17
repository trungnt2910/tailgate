#pragma once

#include <cstring>

#include <lwip/ip_addr.h>

#include <tailgate/net/IpAddress.h>

namespace tailgate::wgengine::netstack::impl
{

inline ip_addr_t NativeAddress(const net::IpAddress& address)
{
    ip_addr_t result{};
    if (address.Family() == net::AddressFamily::Ipv4)
    {
        IP_SET_TYPE_VAL(result, IPADDR_TYPE_V4);
        std::memcpy(&ip_2_ip4(&result)->addr, address.Bytes().data(), address.Bytes().size());
    }
    else
    {
        IP_SET_TYPE_VAL(result, IPADDR_TYPE_V6);
        std::memcpy(ip_2_ip6(&result)->addr, address.Bytes().data(), address.Bytes().size());
    }
    return result;
}

} // namespace tailgate::wgengine::netstack::impl
