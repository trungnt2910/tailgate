#define WIN32_LEAN_AND_MEAN
#include "UwpMachineIdentity.h"

#include <string>

#include <windows.h>

#include <winrt/base.h>

#include <boost/algorithm/string/case_conv.hpp>

namespace tailgate::uwp
{

std::string CollectComputerHostname()
{
    DWORD size = 0;
    (void)GetComputerNameExW(ComputerNamePhysicalDnsHostname, nullptr, &size);
    std::wstring name(size, L'\0');
    std::string hostname = "tailgate-uwp";
    if (!name.empty() &&
        GetComputerNameExW(ComputerNamePhysicalDnsHostname, name.data(), &size) != 0)
    {
        name.resize(size);
        hostname = winrt::to_string(name);
    }
    boost::algorithm::to_lower(hostname);
    return hostname;
}

} // namespace tailgate::uwp
