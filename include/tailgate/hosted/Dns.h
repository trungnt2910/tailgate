#pragma once

#include <optional>
#include <string>
#include <vector>

#include <tailgate/base/Logger.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::hosted
{

enum class DnsStatus
{
    Unhandled,
    Invalid,
    Complete,
};

struct DnsResult
{
    DnsStatus Status = DnsStatus::Unhandled;
    std::optional<Frame> RemoteFrame;
    std::optional<std::vector<std::uint8_t>> LocalPacket;
    std::optional<std::string> Name;
};

class Dns
{
public:
    [[nodiscard]] DnsResult
    ProcessQuery(const std::vector<std::uint8_t>& packet,
                 const tailgate::types::netmap::NetworkConfig& network) const;
    [[nodiscard]] DnsResult
    ProcessResponse(const Frame& frame,
                    const tailgate::types::netmap::NetworkConfig& network) const;

private:
    mutable tailgate::base::Logger m_logger{"hosted-dns"};
};

} // namespace tailgate::hosted
