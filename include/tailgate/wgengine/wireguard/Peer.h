#pragma once

#include <string>
#include <vector>

#include <tailgate/crypto/Keys.h>
#include <tailgate/net/dns/Config.h>

namespace tailgate::wgengine::wireguard
{

struct Peer
{
    tailgate::crypto::PublicKey NodeKey;
    std::string Hostname;
    std::vector<std::string> Addresses;
    tailgate::net::dns::DnsConfig Dns;
};

} // namespace tailgate::wgengine::wireguard
