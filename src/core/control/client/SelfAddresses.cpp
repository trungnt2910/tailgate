#include "SelfAddresses.h"

#include <algorithm>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <tailgate/net/Ipv4Address.h>

namespace tailgate::control::client
{

void ApplySelfAddresses(types::netmap::NetworkConfig& config, const nlohmann::json& node)
{
    std::vector<std::string> addresses;
    const auto entries = node.find("Addresses");
    if (entries != node.end() && entries->is_array())
    {
        for (const auto& entry : *entries)
        {
            const auto address = entry.get<std::string>();
            addresses.push_back(address.substr(0, address.find('/')));
        }
    }
    const auto ipv4 = std::find_if(addresses.begin(),
                                   addresses.end(),
                                   [](const std::string& address)
                                   {
                                       return net::Ipv4Address::TryParse(address).has_value();
                                   });
    config.SelfAddress(
        ipv4 != addresses.end() ? *ipv4 : (addresses.empty() ? std::string() : addresses.front()));
    config.SelfAddresses(std::move(addresses));
}

} // namespace tailgate::control::client
