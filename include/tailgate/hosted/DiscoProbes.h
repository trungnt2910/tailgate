#pragma once

#include <vector>

#include <tailgate/disco/Disco.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::hosted
{

// Builds one disco ping per online peer with valid node and disco keys.
[[nodiscard]] std::vector<PeerPacket>
BuildDiscoProbes(const tailgate::disco::Disco& disco,
                 const std::vector<tailgate::types::netmap::PeerConfig>& peers);

} // namespace tailgate::hosted
