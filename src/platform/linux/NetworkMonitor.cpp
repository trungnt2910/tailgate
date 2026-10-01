#include "NetworkMonitor.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <system_error>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/socket.h>

#include "DataplaneEvents.h"

namespace tailgate::linux_frontend
{

NetworkMonitor::NetworkMonitor(event::EventRegistry& events, std::string excludedInterface)
    : m_excludedInterface(std::move(excludedInterface)),
      m_socket(socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE))
{
    if (m_socket.Fd < 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    sockaddr_nl address{};
    address.nl_family = AF_NETLINK;
    address.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_IPV4_ROUTE |
                        RTMGRP_IPV6_ROUTE;
    if (bind(m_socket.Fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    m_registration = events.Register(m_socket.Fd,
                                     event::EventInterest::Readable,
                                     DataplaneEvent(DataplaneEvent::Kind::Network).Token());
}

void NetworkMonitor::ProcessEvent(const base::Event& event)
{
    if (event.Token != DataplaneEvent(DataplaneEvent::Kind::Network).Token())
    {
        return;
    }
    // Drain a bounded batch. Remaining notifications stay readable in epoll.
    std::array<std::uint8_t, 8192> bytes;
    constexpr std::size_t MaximumNotifications = 16;
    for (std::size_t index = 0; index < MaximumNotifications; ++index)
    {
        const auto count = recv(m_socket.Fd, bytes.data(), bytes.size(), 0);
        if (count < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                break;
            }
            if (errno != ENOBUFS && errno != EINTR)
            {
                throw std::system_error(errno, std::generic_category());
            }
        }
        m_dirty = true;
    }
}

net::netmon::Snapshot NetworkMonitor::Current()
{
    if (!m_dirty)
    {
        return m_snapshot;
    }
    m_dirty = false;
    std::map<std::string, std::vector<std::string>> addresses;
    ifaddrs* raw = nullptr;
    if (getifaddrs(&raw) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    const std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> owner(raw, &freeifaddrs);
    for (auto* entry = raw; entry; entry = entry->ifa_next)
    {
        if (!entry->ifa_addr || !(entry->ifa_flags & IFF_UP) || !(entry->ifa_flags & IFF_RUNNING) ||
            (entry->ifa_flags & IFF_LOOPBACK) || entry->ifa_name == m_excludedInterface)
        {
            continue;
        }
        // Native UDP is currently IPv4; an IPv6-only candidate cannot carry it.
        if (entry->ifa_addr->sa_family != AF_INET)
        {
            continue;
        }
        const auto* address = reinterpret_cast<const sockaddr_in*>(entry->ifa_addr);
        std::array<char, INET_ADDRSTRLEN> text{};
        if (inet_ntop(AF_INET, &address->sin_addr, text.data(), text.size()))
        {
            addresses[entry->ifa_name].emplace_back(text.data());
        }
    }
    std::ifstream routes("/proc/net/route");
    std::string line;
    std::getline(routes, line);
    std::map<std::string, unsigned> metrics;
    while (std::getline(routes, line))
    {
        std::istringstream fields(line);
        std::string name, destination, gateway;
        unsigned flags = 0, references = 0, uses = 0, metric = 0;
        if (!(fields >> name >> destination >> gateway >> std::hex >> flags >> std::dec >>
              references >> uses >> metric) ||
            destination != "00000000" || !(flags & RTF_UP) || !addresses.contains(name))
        {
            continue;
        }
        const auto found = metrics.find(name);
        if (found == metrics.end() || metric < found->second)
        {
            metrics[name] = metric;
        }
    }
    std::vector<std::pair<unsigned, net::netmon::Network>> ranked;
    for (const auto& [name, metric] : metrics)
    {
        auto values = addresses.at(name);
        std::ranges::sort(values);
        ranked.emplace_back(
            metric, net::netmon::Network{.Interface = name, .Addresses = std::move(values)});
    }
    std::ranges::stable_sort(ranked, {}, &decltype(ranked)::value_type::first);
    std::vector<net::netmon::Network> networks;
    for (auto& [metric, network] : ranked)
    {
        networks.push_back(std::move(network));
    }
    if (networks != m_snapshot.Networks)
    {
        ++m_snapshot.Generation;
        m_snapshot.Networks = std::move(networks);
    }
    return m_snapshot;
}

} // namespace tailgate::linux_frontend
