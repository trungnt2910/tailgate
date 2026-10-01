#pragma once

#include <string>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Storage.h>

namespace tailgate::uwp
{

class VpnPhonebook final
{
public:
    static bool SetVpnDeviceType(std::string& bytes);
    static winrt::Windows::Foundation::IAsyncAction
    RepairAsync(winrt::Windows::Storage::StorageFolder folder);
};

} // namespace tailgate::uwp
