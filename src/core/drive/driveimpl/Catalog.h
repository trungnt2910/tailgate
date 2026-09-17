#pragma once

#include <string>
#include <vector>

#include <tailgate/drive/Remote.h>

namespace tailgate::drive::driveimpl
{

struct Catalog
{
    std::string Domain;
    std::string SelfKey;
    bool Access = false;
    std::vector<Remote> Remotes;
    std::vector<std::string> LocalAuthorities{"100.100.100.100:8080", "[fd7a:115c:a1e0::53]:8080"};
};

} // namespace tailgate::drive::driveimpl
