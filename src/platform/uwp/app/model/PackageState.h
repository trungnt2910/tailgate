#pragma once

#include <cstdint>

#include <winrt/base.h>

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

class PackageState final : public ObservableState<PackageState>
{
public:
    [[nodiscard]] winrt::hstring VersionText() const;

    TAILGATE_PROPERTY(Major, std::uint16_t);
    TAILGATE_PROPERTY(Minor, std::uint16_t);
    TAILGATE_PROPERTY(Build, std::uint16_t);
    TAILGATE_PROPERTY(Revision, std::uint16_t);
};

} // namespace tailgate::uwp
