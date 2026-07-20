#include "LinuxCaBundle.h"

#include "LinuxFiles.h"

#include <array>
#include <stdexcept>
#include <sys/stat.h>

namespace tailgate::linux_frontend
{
namespace
{

bool PathExists(const std::string& path)
{
    struct stat info{};
    return stat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode);
}

} // namespace

std::string SystemCaBundlePath()
{
    // Ordered by prevalence: Debian/Ubuntu, Fedora/RHEL, OpenSUSE, and the legacy bundle name.
    static constexpr std::array<const char*, 5> Candidates = {
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/ssl/cert.pem",
    };
    for (const char* candidate : Candidates)
    {
        if (PathExists(candidate))
        {
            return candidate;
        }
    }
    throw std::runtime_error("no system CA bundle was found in the well-known locations");
}

std::vector<std::uint8_t> SystemCaBundle()
{
    return ReadBinaryFile(SystemCaBundlePath());
}

} // namespace tailgate::linux_frontend
