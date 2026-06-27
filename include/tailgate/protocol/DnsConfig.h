#pragma once

#include <string>
#include <vector>

namespace tailgate::protocol
{

struct DnsConfig
{
    std::vector<std::string> Resolvers;
    std::vector<std::string> SearchDomains;
    std::vector<std::string> MatchDomains;
    bool AcceptDns = true;
};

} // namespace tailgate::protocol
