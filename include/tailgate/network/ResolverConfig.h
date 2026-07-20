#pragma once

#include <string>
#include <vector>

namespace tailgate::network
{

[[nodiscard]] std::string ApplyResolverSection(const std::string& contents,
                                               const std::string& resolver,
                                               const std::vector<std::string>& domains);
[[nodiscard]] std::string RemoveResolverSection(const std::string& contents);
[[nodiscard]] std::vector<std::string> ResolverAddresses(const std::string& contents);

} // namespace tailgate::network
