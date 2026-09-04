#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/hosted/Protocol.h>
#include <tailgate/wgengine/Session.h>

namespace tailgate::linux_frontend
{

class HostedDerpRouteTable final
{
public:
    [[nodiscard]] tailgate::hosted::DerpRoute
    Register(tailgate::wgengine::DerpConnectionId connection, std::uint16_t region);
    [[nodiscard]] std::optional<tailgate::wgengine::DerpConnectionId>
    Resolve(const tailgate::hosted::DerpRoute& route) const noexcept;

private:
    struct Entry
    {
        tailgate::hosted::DerpRoute Route;
        tailgate::wgengine::DerpConnectionId Connection = 0;
    };

    std::vector<Entry> m_entries;
};

} // namespace tailgate::linux_frontend
