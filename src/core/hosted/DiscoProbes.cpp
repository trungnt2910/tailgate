#include "tailgate/hosted/DiscoProbes.h"

#include <algorithm>
#include <string_view>

namespace tailgate::hosted
{

std::vector<PeerPacket>
BuildDiscoProbes(const tailgate::disco::Disco& disco,
                 const std::vector<tailgate::types::netmap::PeerConfig>& peers)
{
    constexpr std::string_view NodeKeyPrefix = "nodekey:";
    constexpr std::string_view DiscoKeyPrefix = "discokey:";
    std::vector<PeerPacket> probes;
    for (const tailgate::types::netmap::PeerConfig& peer : peers)
    {
        if (!peer.Online || peer.Key.rfind(NodeKeyPrefix, 0) != 0 ||
            peer.DiscoKey.rfind(DiscoKeyPrefix, 0) != 0)
        {
            continue;
        }
        const std::vector<std::uint8_t> nodeBytes =
            tailgate::crypto::HexToBytes(peer.Key.substr(NodeKeyPrefix.size()));
        const std::vector<std::uint8_t> discoBytes =
            tailgate::crypto::HexToBytes(peer.DiscoKey.substr(DiscoKeyPrefix.size()));
        if (nodeBytes.size() != tailgate::crypto::Bytes32{}.size() ||
            discoBytes.size() != tailgate::crypto::Bytes32{}.size())
        {
            continue;
        }
        tailgate::crypto::Bytes32 nodeKey{};
        tailgate::crypto::Bytes32 discoKey{};
        std::copy(nodeBytes.begin(), nodeBytes.end(), nodeKey.begin());
        std::copy(discoBytes.begin(), discoBytes.end(), discoKey.begin());
        probes.push_back(PeerPacket{
            .Peer = nodeKey,
            .Payload = disco.BuildPing(discoKey, disco.NewTransactionId()),
            .Disco = true,
        });
    }
    return probes;
}

} // namespace tailgate::hosted
