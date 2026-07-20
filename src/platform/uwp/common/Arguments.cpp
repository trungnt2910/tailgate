#include "common/Arguments.h"

#include <cstddef>
#include <format>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include <winrt/base.h>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/case_conv.hpp>

namespace tailgate::uwp
{
namespace
{

std::string PercentDecode(const std::string& value)
{
    std::string result;
    for (std::size_t i = 0; i < value.size(); ++i)
    {
        if (value[i] == '%' && i + 2 < value.size())
        {
            std::string decoded;
            try
            {
                boost::algorithm::unhex(value.begin() + static_cast<std::ptrdiff_t>(i + 1),
                                        value.begin() + static_cast<std::ptrdiff_t>(i + 3),
                                        std::back_inserter(decoded));
            }
            catch (const boost::algorithm::hex_decode_error&)
            {
            }
            if (!decoded.empty())
            {
                result += decoded;
                i += 2;
                continue;
            }
        }
        result.push_back(value[i] == '+' ? ' ' : value[i]);
    }
    return result;
}

} // namespace

std::vector<std::string> Arguments::FromUri(const winrt::Windows::Foundation::Uri& uri)
{
    std::string command = winrt::to_string(uri.Host());
    boost::algorithm::to_lower(command);
    std::vector<std::string> arguments{std::move(command)};
    std::string query = winrt::to_string(uri.Query());
    if (!query.empty() && query.front() == '?')
    {
        query.erase(query.begin());
    }
    std::size_t start = 0;
    while (start < query.size())
    {
        const std::size_t end = query.find('&', start);
        const std::string item = query.substr(start, end - start);
        const std::size_t equals = item.find('=');
        const std::string name = PercentDecode(item.substr(0, equals));
        if (!name.empty())
        {
            if (name == "--" && equals != std::string::npos)
            {
                arguments.push_back(PercentDecode(item.substr(equals + 1)));
            }
            else if (equals == std::string::npos)
            {
                arguments.push_back(std::format("--{}", name));
            }
            else
            {
                arguments.push_back(
                    std::format("--{}={}", name, PercentDecode(item.substr(equals + 1))));
            }
        }
        if (end == std::string::npos)
        {
            break;
        }
        start = end + 1;
    }
    return arguments;
}

} // namespace tailgate::uwp
