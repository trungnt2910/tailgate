#include <tailgate/net/dns/ResolverConfig.h>

#include <algorithm>
#include <format>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/split.hpp>

#include <tailgate/net/packet/Ipv4.h>

namespace tailgate::net::dns
{
namespace
{

constexpr const char* SectionStart = "# TailgateResolverSectionStart";
constexpr const char* SectionEnd = "# TailgateResolverSectionEnd";

} // namespace

std::string RemoveResolverSection(const std::string& contents)
{
    const std::size_t start = contents.find(SectionStart);
    if (start == std::string::npos)
    {
        return contents;
    }
    const std::size_t markerEnd = contents.find(SectionEnd, start);
    if (markerEnd == std::string::npos)
    {
        return contents;
    }
    std::size_t end = contents.find('\n', markerEnd);
    end = end == std::string::npos ? contents.size() : end + 1;
    std::string result = contents.substr(0, start) + contents.substr(end);
    if (start == 0 && !result.empty() && result.front() == '\n')
    {
        result.erase(result.begin());
    }
    return result;
}

std::string ApplyResolverSection(const std::string& contents,
                                 const std::string& resolver,
                                 const std::vector<std::string>& domains)
{
    std::string search;
    if (!domains.empty())
    {
        search = std::format("search {}\n", boost::algorithm::join(domains, " "));
    }
    return std::format("{}\n# This section is managed by Tailgate. Do not edit it manually.\n"
                       "nameserver {}\n{}options ndots:1\n{}\n\n{}",
                       SectionStart,
                       resolver,
                       search,
                       SectionEnd,
                       RemoveResolverSection(contents));
}

std::vector<std::string> ResolverAddresses(const std::string& contents)
{
    std::vector<std::string> result;
    std::vector<std::string> lines;
    boost::algorithm::split(
        lines, RemoveResolverSection(contents), boost::algorithm::is_any_of("\n"));
    for (const std::string& line : lines)
    {
        std::vector<std::string> fields;
        boost::algorithm::split(fields,
                                line,
                                boost::algorithm::is_any_of(" \t\r"),
                                boost::algorithm::token_compress_on);
        fields.erase(std::remove(fields.begin(), fields.end(), std::string{}), fields.end());
        if (fields.size() >= 2 && fields[0] == "nameserver" &&
            tailgate::net::packet::ParseIpv4(fields[1]))
        {
            result.push_back(fields[1]);
        }
    }
    return result;
}

} // namespace tailgate::net::dns
