#pragma once

#include <winrt/Windows.Foundation.h>

namespace tailgate::uwp::bg
{

[[nodiscard]] winrt::Windows::Foundation::IInspectable CreateVpnBackgroundTask();

} // namespace tailgate::uwp::bg
