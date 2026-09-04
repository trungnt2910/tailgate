#pragma once

#include <vector>

#include <tailgate/disco/Disco.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::hosted
{

// Builds a DERP ping for each usable peer, then opens each known UDP path and advertises the
// hosted server's candidates to that peer over DERP.
[[nodiscard]] std::vector<PeerPacket>
BuildDiscoProbes(const tailgate::disco::Disco& disco,
                 const std::vector<tailgate::types::netmap::PeerConfig>& peers,
                 const std::vector<tailgate::net::Endpoint>& localCandidates);

// Builds only the direct-path bootstrap portion. This is used to answer an incoming DERP ping by
// immediately opening the reverse UDP path and sending CallMeMaybe.
[[nodiscard]] std::vector<PeerPacket>
BuildDiscoEndpointProbes(const tailgate::disco::Disco& disco,
                         const tailgate::types::netmap::PeerConfig& peer,
                         const std::vector<tailgate::net::Endpoint>& localCandidates);

} // namespace tailgate::hosted
