#include "TrackerImpl.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <format>
#include <optional>
#include <string_view>
#include <utility>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/net/packet/Tsmp.h>

namespace tailgate::wgengine::ping::impl
{
namespace
{

constexpr std::string_view NodeKeyPrefix = "nodekey:";
constexpr std::string_view DiscoKeyPrefix = "discokey:";

std::optional<tailgate::crypto::Bytes32> ParseKey(const std::string& value, std::string_view prefix)
{
    if (!value.starts_with(prefix))
    {
        return std::nullopt;
    }
    const std::string_view encoded(value.data() + prefix.size(), value.size() - prefix.size());
    constexpr std::size_t EncodedKeySize = tailgate::crypto::Bytes32{}.size() * 2;
    if (encoded.size() != EncodedKeySize ||
        !std::ranges::all_of(encoded,
                             [](unsigned char character)
                             {
                                 return std::isxdigit(character) != 0;
                             }))
    {
        return std::nullopt;
    }
    const std::vector<std::uint8_t> bytes = tailgate::crypto::HexToBytes(std::string(encoded));
    tailgate::crypto::Bytes32 result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

std::string RelayLabel(const tailgate::types::netmap::PeerConfig& peer,
                       const std::string& requested)
{
    if (!requested.empty())
    {
        return requested;
    }
    return peer.DerpCode().empty() ? std::format("derp-{}", peer.DerpRegion()) : peer.DerpCode();
}

} // namespace

StartResult TrackerImpl::Start(const Request& request,
                               const tailgate::types::netmap::NetworkConfig& network,
                               tailgate::disco::Disco& disco,
                               TimePoint now)
{
    if (std::ranges::any_of(m_pending,
                            [&](const Pending& pending)
                            {
                                return pending.RequestState.Id == request.Id;
                            }))
    {
        return {.Status = StartStatus::DuplicateRequest, .Outbound = std::nullopt};
    }
    const std::optional<std::size_t> selected = network.FindPeer(request.Target);
    if (!selected)
    {
        return {.Status = StartStatus::NoMatchingPeer, .Outbound = std::nullopt};
    }
    const tailgate::types::netmap::PeerConfig& peer = network.Peers()[*selected];
    const std::optional<tailgate::crypto::Bytes32> nodeKey = ParseKey(peer.Key(), NodeKeyPrefix);
    if (!nodeKey)
    {
        return {.Status = StartStatus::NoNodeKey, .Outbound = std::nullopt};
    }

    Pending pending{
        .RequestState = request,
        .Peer = *nodeKey,
        .DiscoTransaction = {},
        .TsmpToken = {},
        .Started = now,
        .PeerName = peer.Name(),
        .PeerAddress = peer.Address(),
        .Relay = RelayLabel(peer, request.Relay),
    };
    Probe probe{.RequestId = request.Id, .Peer = *nodeKey, .Payload = {}, .Disco = false};
    if (request.PingMode == Mode::Disco)
    {
        const std::optional<tailgate::crypto::Bytes32> discoKey =
            ParseKey(peer.DiscoKey(), DiscoKeyPrefix);
        if (!discoKey)
        {
            return {.Status = StartStatus::NoDiscoKey, .Outbound = std::nullopt};
        }
        pending.DiscoTransaction = disco.NewTransactionId();
        probe.Payload = disco.BuildPing(*discoKey, pending.DiscoTransaction);
        probe.Disco = true;
    }
    else
    {
        const std::optional<tailgate::net::Ipv4Address> source =
            tailgate::net::Ipv4Address::TryParse(network.SelfAddress());
        const std::optional<tailgate::net::Ipv4Address> destination =
            tailgate::net::Ipv4Address::TryParse(peer.Address());
        if (!source || !destination)
        {
            return {.Status = StartStatus::InvalidAddress, .Outbound = std::nullopt};
        }
        const tailgate::crypto::Bytes32 random = tailgate::crypto::GeneratePrivateKey();
        std::copy_n(random.begin(), pending.TsmpToken.size(), pending.TsmpToken.begin());
        probe.Payload = tailgate::net::packet::TsmpPacket::BuildPing(
            source->HostOrder(), destination->HostOrder(), pending.TsmpToken);
    }
    m_pending.push_back(std::move(pending));
    return {.Status = StartStatus::Ready, .Outbound = std::move(probe)};
}

std::optional<Result>
TrackerImpl::CompleteDisco(const tailgate::crypto::Bytes32& peer,
                           const tailgate::disco::Disco::TransactionId& transaction,
                           std::uint16_t peerApiPort,
                           TimePoint now)
{
    const auto pending =
        std::ranges::find_if(m_pending,
                             [&](const Pending& candidate)
                             {
                                 return candidate.RequestState.PingMode == Mode::Disco &&
                                        candidate.Peer == peer &&
                                        candidate.DiscoTransaction == transaction;
                             });
    if (pending == m_pending.end())
    {
        return std::nullopt;
    }
    Result result = Complete(*pending, true, peerApiPort, now);
    m_pending.erase(pending);
    return result;
}

std::optional<Result> TrackerImpl::CompleteTsmp(const tailgate::net::packet::TsmpToken& token,
                                                std::uint16_t peerApiPort,
                                                TimePoint now)
{
    const auto pending = std::ranges::find_if(
        m_pending,
        [&](const Pending& candidate)
        {
            return candidate.RequestState.PingMode == Mode::Tsmp && candidate.TsmpToken == token;
        });
    if (pending == m_pending.end())
    {
        return std::nullopt;
    }
    Result result = Complete(*pending, true, peerApiPort, now);
    m_pending.erase(pending);
    return result;
}

std::vector<Result> TrackerImpl::Expire(TimePoint now)
{
    std::vector<Result> results;
    for (const Pending& pending : m_pending)
    {
        if (now - pending.Started >= pending.RequestState.Timeout)
        {
            results.push_back(Complete(pending, false, 0, now));
        }
    }
    std::erase_if(m_pending,
                  [&](const Pending& pending)
                  {
                      return now - pending.Started >= pending.RequestState.Timeout;
                  });
    return results;
}

void TrackerImpl::Reset() noexcept
{
    m_pending.clear();
}

Result TrackerImpl::Complete(const Pending& pending,
                             bool responded,
                             std::uint16_t peerApiPort,
                             TimePoint now) const
{
    return Result{
        .RequestId = pending.RequestState.Id,
        .Responded = responded,
        .Latency = now - pending.Started,
        .PeerName = pending.PeerName,
        .PeerAddress = pending.PeerAddress,
        .Relay = pending.Relay,
        .PeerApiPort = peerApiPort,
    };
}

} // namespace tailgate::wgengine::ping::impl
