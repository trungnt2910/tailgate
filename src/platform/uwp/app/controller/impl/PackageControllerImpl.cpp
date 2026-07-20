#include "app/controller/impl/PackageControllerImpl.h"

#include <winrt/Windows.ApplicationModel.h>

namespace tailgate::uwp
{

PackageControllerImpl::PackageControllerImpl()
{
    const auto version = winrt::Windows::ApplicationModel::Package::Current().Id().Version();
    m_state.Update(
        [&](PackageState& state)
        {
            state.Major(version.Major);
            state.Minor(version.Minor);
            state.Build(version.Build);
            state.Revision(version.Revision);
        });
}

const PackageState& PackageControllerImpl::GetState() const noexcept
{
    return m_state;
}

} // namespace tailgate::uwp
