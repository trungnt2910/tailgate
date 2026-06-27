#pragma once

#include "tailgate/protocol/DnsConfig.h"
#include "tailgate/protocol/Keys.h"

#include <string>
#include <vector>

namespace tailgate::protocol
{

struct Peer
{
    PublicKey NodeKey;
    std::string Hostname;
    std::vector<std::string> Addresses;
    DnsConfig Dns;
};

} // namespace tailgate::protocol
