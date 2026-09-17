#include "CapabilityFilters.h"

#include <nlohmann/json.hpp>

namespace tailgate::control::client
{
namespace
{

std::vector<net::IpRange> Ranges(const nlohmann::json& list, bool sources)
{
    if (!list.is_array())
    {
        throw CapabilityFilterError();
    }
    std::vector<net::IpRange> result;
    for (const auto& entry : list)
    {
        const auto text = entry.get<std::string>();
        if (sources && text == "*")
        {
            result.push_back(*net::IpRange::TryParse("0.0.0.0/0"));
            result.push_back(*net::IpRange::TryParse("::/0"));
        }
        else if (sources && text.starts_with("cap:"))
        {
            // Upstream CapsWithValues matches SrcsContains, not SrcCaps; node
            // capability selectors do not independently confer application grants.
            continue;
        }
        else if (const auto range = net::IpRange::TryParse(text))
        {
            result.push_back(*range);
        }
        else
        {
            throw CapabilityFilterError();
        }
    }
    return result;
}

std::vector<types::netmap::CapabilityPresenceGrant> Parse(const nlohmann::json& rules)
{
    if (!rules.is_array())
    {
        throw CapabilityFilterError();
    }
    std::vector<types::netmap::CapabilityPresenceGrant> result;
    for (const auto& rule : rules)
    {
        const auto grants = rule.find("CapGrant");
        if (grants == rule.end() || grants->is_null() || grants->empty())
        {
            continue;
        }
        if (!grants->is_array() || (rule.contains("SrcBits") && !rule.at("SrcBits").empty()) ||
            (rule.contains("DstPorts") && !rule.at("DstPorts").empty()))
        {
            throw CapabilityFilterError();
        }
        const auto sources = Ranges(rule.at("SrcIPs"), true);
        for (const auto& source : *grants)
        {
            types::netmap::CapabilityPresenceGrant grant;
            grant.Sources = sources;
            grant.Destinations = Ranges(source.at("Dsts"), false);
            if (source.contains("Caps") && !source.at("Caps").is_null())
            {
                grant.Names = source.at("Caps").get<std::vector<std::string>>();
            }
            if (source.contains("CapMap") && !source.at("CapMap").is_null())
            {
                if (!source.at("CapMap").is_object())
                {
                    throw CapabilityFilterError();
                }
                for (const auto& [name, values] : source.at("CapMap").items())
                {
                    (void)values;
                    grant.Names.push_back(name);
                }
            }
            result.push_back(std::move(grant));
        }
    }
    return result;
}

} // namespace

const char* CapabilityFilterError::what() const noexcept
{
    return "invalid capability filter";
}

bool ApplyCapabilityFilterUpdate(types::netmap::NetworkConfig& configuration,
                                 const nlohmann::json& map)
{
    auto filters = configuration.CapabilityFilters();
    bool changed = false;
    if (map.contains("PacketFilter") && !map.at("PacketFilter").is_null())
    {
        filters["base"] = Parse(map.at("PacketFilter"));
        changed = true;
    }
    if (map.contains("PacketFilters") && !map.at("PacketFilters").is_null())
    {
        const auto& updates = map.at("PacketFilters");
        if (!updates.is_object())
        {
            throw CapabilityFilterError();
        }
        if (updates.contains("*") && updates.at("*").is_null())
        {
            filters.clear();
        }
        for (const auto& [name, rules] : updates.items())
        {
            if (name == "*")
            {
                continue;
            }
            if (rules.is_null())
            {
                filters.erase(name);
            }
            else
            {
                filters[name] = Parse(rules);
            }
        }
        changed = true;
    }
    if (changed)
    {
        configuration.CapabilityFilters(std::move(filters));
    }
    return changed;
}

} // namespace tailgate::control::client
