#pragma once

#include <optional>

#include "app/ui/AppResources.h"
#include "common/UwpAliases.h"

namespace tailgate::uwp
{

class ButtonFactory final
{
public:
    explicit ButtonFactory(AppResources& resources);

    [[nodiscard]] controls::Button CircleIcon(const winrt::hstring& glyph,
                                              const winrt::hstring& label,
                                              std::optional<double> iconSize = std::nullopt) const;
    [[nodiscard]] controls::Button Icon(const winrt::hstring& glyph,
                                        const winrt::hstring& label) const;
    [[nodiscard]] controls::Button PrimaryText(const winrt::hstring& value) const;
    [[nodiscard]] controls::Button Text(const winrt::hstring& value) const;

private:
    AppResources& m_resources;
};

} // namespace tailgate::uwp
