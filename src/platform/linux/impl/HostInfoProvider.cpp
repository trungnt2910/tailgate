#include "HostInfoProvider.h"

#include <algorithm>
#include <cctype>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <sys/utsname.h>
#include <unistd.h>

#include <tailgate/crypto/Crypto.h>

namespace tailgate::linux_frontend::impl
{
namespace
{

constexpr const char* TailgateVersion = "Tailgate";

std::string GenerateLogId()
{
    constexpr std::size_t LogIdBytes = 32;
    std::random_device random;
    std::vector<std::uint8_t> bytes(LogIdBytes);
    for (std::uint8_t& byte : bytes)
    {
        byte = static_cast<std::uint8_t>(random());
    }
    return tailgate::crypto::BytesToHex(bytes.data(), bytes.size());
}

} // namespace

tailgate::control::client::HostInfo HostInfoProvider::GetHostInfo()
{
    const long maximumHostnameLength = sysconf(_SC_HOST_NAME_MAX);
    const std::size_t hostnameCapacity =
        maximumHostnameLength > 0 ? static_cast<std::size_t>(maximumHostnameLength) + 1 : 256;
    std::vector<char> hostname(hostnameCapacity);
    if (gethostname(hostname.data(), hostname.size()) != 0 || hostname.back() != '\0')
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
    std::ranges::transform(operatingSystem,
                           operatingSystem.begin(),
                           [](unsigned char value)
                           {
                               return static_cast<char>(std::tolower(value));
                           });

    tailgate::control::client::HostInfo result(
        hostname.data(), std::move(operatingSystem), system.release, std::move(architecture));
    result.SetClientMetadata(TailgateVersion, GenerateLogId(), GenerateLogId());
    return result;
}

} // namespace tailgate::linux_frontend::impl
