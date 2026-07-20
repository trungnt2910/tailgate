#include "app/model/PackageState.h"

#include <format>

namespace tailgate::uwp
{

winrt::hstring PackageState::VersionText() const
{
    return winrt::hstring(std::format(L"{}.{}.{}.{}", Major(), Minor(), Build(), Revision()));
}

} // namespace tailgate::uwp
