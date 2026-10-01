#pragma once

#include <bitset>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

#include <tailgate/base/TimeProvider.h>
#include <tailgate/crypto/Random.h>
#include <tailgate/ipn/ipnlocal/NetworkPolicy.h>
#include <tailgate/net/Endpoint.h>

namespace tailgate::ipn::ipnlocal
{

enum class DnsForwardStatus
{
    Ready,
    InvalidQuery,
    UnsupportedResolver,
    Full,
};

struct DnsReply
{
    net::Endpoint Client;
    std::vector<std::uint8_t> Payload;
};

struct DnsForward
{
    DnsForwardStatus Status = DnsForwardStatus::InvalidQuery;
    net::Endpoint Resolver;
    std::vector<std::uint8_t> Payload;
    std::optional<std::vector<std::uint8_t>> TunnelPacket;
    std::optional<DnsReply> LocalReply;
};

// A request retains its resolver and local address across policy changes. Wire IDs
// distinguish clients sharing a UDP transport, even when their DNS IDs collide.
class DnsForwarder final
{
public:
    using TimePoint = base::TimeProvider::TimePoint;
    explicit DnsForwarder(crypto::Random& random);
    [[nodiscard]] DnsForward Begin(net::Endpoint client,
                                   std::vector<std::uint8_t> payload,
                                   const NetworkPolicy& policy,
                                   const std::vector<std::string>& originalResolvers,
                                   TimePoint now);
    [[nodiscard]] std::optional<DnsReply> CompletePacket(const std::vector<std::uint8_t>& packet);
    [[nodiscard]] std::optional<DnsReply> CompleteDatagram(net::Endpoint source,
                                                           std::vector<std::uint8_t> payload);
    void Reset() noexcept;
    void Expire(TimePoint now);
    [[nodiscard]] std::optional<TimePoint> NextDeadline() const;

private:
    struct Pending
    {
        net::Endpoint Client;
        net::Ipv4Address Self;
        net::Ipv4Address Resolver;
        std::uint16_t OriginalId = 0;
        std::uint16_t WireId = 0;
        bool Tunneled = false;
        TimePoint Started;
    };

    [[nodiscard]] DnsReply Finish(std::vector<Pending>::iterator pending,
                                  std::vector<std::uint8_t> payload);
    static constexpr std::size_t WireIdCount =
        std::size_t{std::numeric_limits<std::uint16_t>::max()} + 1;
    std::vector<Pending> m_pending;
    std::bitset<WireIdCount> m_wireIds;
    crypto::Random& m_random;
};

} // namespace tailgate::ipn::ipnlocal
