#include "HostedDerpRouteTable.h"

#include <algorithm>
#include <atomic>
#include <stdexcept>

namespace tailgate::linux_frontend
{
namespace
{

std::atomic<std::uint64_t> NextRouteToken = 1;

}

tailgate::hosted::DerpRoute
HostedDerpRouteTable::Register(tailgate::wgengine::DerpConnectionId connection,
                               std::uint16_t region)
{
    if (region == 0)
    {
        throw std::invalid_argument("Hosted DERP route has no region.");
    }
    const std::uint64_t token = NextRouteToken.fetch_add(1, std::memory_order_relaxed);
    if (token == 0)
    {
        throw std::overflow_error("Hosted DERP route tokens are exhausted.");
    }
    const tailgate::hosted::DerpRoute route(token, region);
    m_entries.push_back(Entry{
        .Route = route,
        .Connection = connection,
    });
    return route;
}

std::optional<tailgate::wgengine::DerpConnectionId>
HostedDerpRouteTable::Resolve(const tailgate::hosted::DerpRoute& route) const noexcept
{
    const auto found = std::ranges::find_if(m_entries,
                                            [&](const Entry& entry)
                                            {
                                                return entry.Route == route;
                                            });
    return found == m_entries.end() ? std::nullopt : std::optional(found->Connection);
}

} // namespace tailgate::linux_frontend
