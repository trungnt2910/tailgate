#pragma once

#include "app/ui/AppResources.h"
#include "common/UwpAliases.h"

namespace tailgate::uwp
{

class UiFactory final
{
public:
    explicit UiFactory(AppResources& resources);

    [[nodiscard]] controls::FontIcon FluentIcon(const winrt::hstring& glyph) const;
    [[nodiscard]] controls::ListViewItem ListHeader(const winrt::hstring& title) const;
    [[nodiscard]] controls::ListViewItem ListItem(const xaml::UIElement& content) const;
    [[nodiscard]] static xaml::Thickness
    Margin(double left, double top, double right, double bottom);
    [[nodiscard]] controls::Grid PageChrome(const winrt::hstring& title,
                                            const xaml::UIElement& content) const;
    [[nodiscard]] controls::ListView PageListView() const;
    [[nodiscard]] xaml::UIElement
    ProfilePicture(double size, const media::ImageSource& imageSource = nullptr) const;
    [[nodiscard]] controls::ListViewItem SectionSpacing() const;
    [[nodiscard]] shapes::Ellipse StatusDot(bool online) const;
    [[nodiscard]] controls::TextBlock Text(const winrt::hstring& value, AppStyle style) const;
    [[nodiscard]] controls::Grid ValueWithIconRow(const winrt::hstring& primary,
                                                  const winrt::hstring& secondary,
                                                  const wchar_t* glyph,
                                                  media::Brush iconForeground = nullptr) const;

private:
    AppResources& m_resources;
};

} // namespace tailgate::uwp
