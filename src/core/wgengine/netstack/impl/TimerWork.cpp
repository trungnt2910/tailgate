#include "TimerWork.h"

#include <span>

#include <lwip/netif.h>
#include <lwip/priv/nd6_priv.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/stats.h>

namespace tailgate::wgengine::netstack::impl
{
namespace
{

// Keep this activity check in step with the cyclic timers enabled by the port.
// New protocols need their own activity check before idle wakeups can be suppressed.
static_assert(!LWIP_ARP && !LWIP_DHCP && !LWIP_ACD && !LWIP_IGMP && !LWIP_DNS && !LWIP_IPV6_MLD &&
              !LWIP_IPV6_DHCP6 && !LWIP_IPV6_SEND_ROUTER_SOLICIT);
static_assert(MEMP_STATS && IP_REASSEMBLY && LWIP_IPV6_REASS);

bool HasNeighborDiscoveryWork() noexcept
{
    for (const auto& neighbor : std::span(neighbor_cache, LWIP_ND6_NUM_NEIGHBORS))
    {
        if (neighbor.state != ND6_NO_ENTRY)
        {
            return true;
        }
    }
    for (const auto& destination : std::span(destination_cache, LWIP_ND6_NUM_DESTINATIONS))
    {
        if (!ip6_addr_isany(&destination.destination_addr))
        {
            return true;
        }
    }
    for (const auto& prefix : std::span(prefix_list, LWIP_ND6_NUM_PREFIXES))
    {
        if (prefix.netif != nullptr)
        {
            return true;
        }
    }
    for (const auto& router : std::span(default_router_list, LWIP_ND6_NUM_ROUTERS))
    {
        if (router.neighbor_entry != nullptr)
        {
            return true;
        }
    }
    for (const auto* interface = netif_list; interface != nullptr; interface = interface->next)
    {
        for (unsigned index = 0; index < LWIP_IPV6_NUM_ADDRESSES; ++index)
        {
            const auto state = netif_ip6_addr_state(interface, index);
            if (ip6_addr_istentative(state) ||
                (!ip6_addr_isinvalid(state) && !netif_ip6_addr_isstatic(interface, index)))
            {
                return true;
            }
        }
    }
    return false;
}

} // namespace

bool HasTimerWork() noexcept
{
    // Upstream owns the queues and their accounting, including failed allocations,
    // completed datagrams and eviction. Do not mirror fragment lifetimes in Tailgate.
    return tcp_active_pcbs != nullptr || tcp_tw_pcbs != nullptr ||
           MEMP_STATS_GET(used, MEMP_REASSDATA) != 0 ||
           MEMP_STATS_GET(used, MEMP_IP6_REASSDATA) != 0 || HasNeighborDiscoveryWork();
}

} // namespace tailgate::wgengine::netstack::impl
