#include "LinuxHost.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>
#include <string>

#include <sys/utsname.h>
#include <unistd.h>

namespace tailgate::linux_frontend
{

tailgate::protocol::HostInfo CollectHostInfo()
{
    std::array<char, 256> hostname{};
    if (gethostname(hostname.data(), hostname.size()) != 0)
    {
        throw std::runtime_error("failed to read the host name");
    }

    utsname system{};
    if (uname(&system) != 0)
    {
        throw std::runtime_error("failed to read OS information");
    }

    std::string architecture = system.machine;
    if (architecture == "x86_64")
    {
        architecture = "amd64";
    }
    else if (architecture == "aarch64")
    {
        architecture = "arm64";
    }

    std::string operatingSystem = system.sysname;
    std::transform(operatingSystem.begin(),
                   operatingSystem.end(),
                   operatingSystem.begin(),
                   [](unsigned char value)
                   {
                       return static_cast<char>(std::tolower(value));
                   });

    return {
        hostname.data(),
        std::move(operatingSystem),
        system.release,
        std::move(architecture),
        "Tailgate",
    };
}

} // namespace tailgate::linux_frontend
