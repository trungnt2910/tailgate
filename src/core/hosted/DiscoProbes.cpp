#include "tailgate/hosted/DiscoProbes.h"

#include <algorithm>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

namespace tailgate::hosted
{
namespace
{

struct PeerKeys
{
    tailgate::crypto::Bytes32 Node{};
    tailgate::crypto::Bytes32 Disco{};
};

std::optional<PeerKeys> DecodePeerKeys(const tailgate::types::netmap::PeerConfig& peer)
{
    constexpr std::string_view NodeKeyPrefix = "nodekey:";
    constexpr std::string_view DiscoKeyPrefix = "discokey:";
    if (!peer.Online() || peer.Key().rfind(NodeKeyPrefix, 0) != 0 ||
        peer.DiscoKey().rfind(DiscoKeyPrefix, 0) != 0)
    {
        return std::nullopt;
    }
    const std::vector<std::uint8_t> nodeBytes =
        tailgate::crypto::HexToBytes(peer.Key().substr(NodeKeyPrefix.size()));
    const std::vector<std::uint8_t> discoBytes =
        tailgate::crypto::HexToBytes(peer.DiscoKey().substr(DiscoKeyPrefix.size()));
    if (nodeBytes.size() != tailgate::crypto::Bytes32{}.size() ||
        discoBytes.size() != tailgate::crypto::Bytes32{}.size())
    {
        return std::nullopt;
    }
    PeerKeys keys;
    std::copy(nodeBytes.begin(), nodeBytes.end(), keys.Node.begin());
    std::copy(discoBytes.begin(), discoBytes.end(), keys.Disco.begin());
    return keys;
}

} // namespace

std::vector<PeerPacket>
BuildDiscoProbes(const tailgate::disco::Disco& disco,
                 const std::vector<tailgate::types::netmap::PeerConfig>& peers,
                 const std::vector<tailgate::net::Endpoint>& localCandidates)
{
    std::vector<PeerPacket> probes;
    for (const tailgate::types::netmap::PeerConfig& peer : peers)
    {
        const std::optional<PeerKeys> keys = DecodePeerKeys(peer);
        if (!keys)
        {
            continue;
        }
        probes.emplace_back(keys->Node,
                            disco.BuildPing(keys->Disco, disco.NewTransactionId()),
                            /* control = */ false,
                            /* disco = */ true);
        std::vector<PeerPacket> endpointProbes =
            BuildDiscoEndpointProbes(disco, peer, localCandidates);
        probes.insert(probes.end(),
                      std::make_move_iterator(endpointProbes.begin()),
                      std::make_move_iterator(endpointProbes.end()));
    }
    return probes;
}

std::vector<PeerPacket>
BuildDiscoEndpointProbes(const tailgate::disco::Disco& disco,
                         const tailgate::types::netmap::PeerConfig& peer,
                         const std::vector<tailgate::net::Endpoint>& localCandidates)
{
    const std::optional<PeerKeys> keys = DecodePeerKeys(peer);
    if (!keys || localCandidates.empty())
    {
        return {};
    }
    std::vector<PeerPacket> probes;
    for (const std::string& endpointText : peer.Endpoints())
    {
        const std::optional<tailgate::net::Endpoint> endpoint =
            tailgate::net::Endpoint::TryParse(endpointText);
        if (!endpoint || endpoint->Address().HostOrder() == 0 || endpoint->Port() == 0)
        {
            continue;
        }
        probes.emplace_back(keys->Node,
                            disco.BuildPing(keys->Disco, disco.NewTransactionId()),
                            false,
                            true,
                            endpoint->Address().HostOrder(),
                            endpoint->Port());
    }
    if (!probes.empty())
    {
        probes.emplace_back(keys->Node,
                            disco.BuildCallMeMaybe(keys->Disco, localCandidates),
                            /* control = */ false,
                            /* disco = */ true);
    }
    return probes;
}

} // namespace tailgate::hosted
