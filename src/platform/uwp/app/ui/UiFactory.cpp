#include "app/ui/UiFactory.h"

#include <cstdint>

#include "app/ui/Glyphs.h"

namespace tailgate::uwp
{

namespace
{

controls::ScrollViewer FindScrollViewer(const xaml::DependencyObject& root)
{
    const std::int32_t count = media::VisualTreeHelper::GetChildrenCount(root);
    for (std::int32_t index = 0; index < count; ++index)
    {
        const auto child = media::VisualTreeHelper::GetChild(root, index);
        if (const auto viewer = child.try_as<controls::ScrollViewer>())
        {
            return viewer;
        }
        if (const auto viewer = FindScrollViewer(child))
        {
            return viewer;
        }
    }
    return nullptr;
}

} // namespace

UiFactory::UiFactory(AppResources& resources) : m_resources(resources)
{
}

controls::FontIcon UiFactory::FluentIcon(const winrt::hstring& glyph) const
{
    controls::FontIcon icon;
    icon.Glyph(glyph);
    icon.Style(m_resources.Style(AppStyle::Icon));
    return icon;
}

controls::ListViewItem UiFactory::ListHeader(const winrt::hstring& title) const
{
    controls::ListViewHeaderItem header;
    auto label = Text(title, AppStyle::TextCaptionStrong);
    header.Content(label);
    header.Style(m_resources.Style(AppStyle::ListHeader));

    controls::ListViewItem item;
    item.Content(header);
    item.Style(m_resources.Style(AppStyle::ListHeaderContainer));
    return item;
}

controls::ListViewItem UiFactory::ListItem(const xaml::UIElement& content) const
{
    controls::ListViewItem item;
    item.Content(content);
    item.Style(m_resources.Style(AppStyle::ListItem));
    return item;
}

xaml::Thickness UiFactory::Margin(double left, double top, double right, double bottom)
{
    xaml::Thickness result;
    result.Left = left;
    result.Top = top;
    result.Right = right;
    result.Bottom = bottom;
    return result;
}

controls::Grid UiFactory::PageChrome(const winrt::hstring& title,
                                     const xaml::UIElement& content) const
{
    controls::Grid root;
    root.Style(m_resources.Style(AppStyle::Page));
    auto titleRow = controls::RowDefinition();
    titleRow.Height(xaml::GridLengthHelper::Auto());
    root.RowDefinitions().Append(titleRow);
    auto contentRow = controls::RowDefinition();
    contentRow.Height(xaml::GridLengthHelper::FromValueAndType(1, xaml::GridUnitType::Star));
    root.RowDefinitions().Append(contentRow);

    auto titleBlock = Text(title, AppStyle::TextPageTitle);
    titleBlock.Margin(m_resources.Thickness(AppThickness::PageTitleMargin));
    root.Children().Append(titleBlock);
    controls::Grid::SetRow(content.as<xaml::FrameworkElement>(), 1);
    root.Children().Append(content);
    return root;
}

controls::ListView UiFactory::PageListView() const
{
    controls::ListView list;
    list.SelectionMode(controls::ListViewSelectionMode::None);
    list.IsItemClickEnabled(true);
    const double gutterWidth = m_resources.Double(AppDouble::ListScrollbarGutter);
    list.Loaded(
        [gutterWidth](const foundation::IInspectable& sender, const auto&)
        {
            const auto loadedList = sender.as<controls::ListView>();
            const auto viewer = FindScrollViewer(loadedList);
            if (viewer == nullptr)
            {
                return;
            }
            const auto weakList = winrt::make_weak(loadedList);
            const auto applyGutter =
                [weakList, gutterWidth](const controls::ScrollViewer& scrollViewer)
            {
                if (const auto trackedList = weakList.get())
                {
                    const double gutter = scrollViewer.ScrollableHeight() > 0 ? gutterWidth : 0;
                    trackedList.Padding(Margin(0, 0, gutter, 0));
                }
            };
            applyGutter(viewer);
            viewer.RegisterPropertyChangedCallback(
                controls::ScrollViewer::ScrollableHeightProperty(),
                [applyGutter](const xaml::DependencyObject& changed, const auto&)
                {
                    applyGutter(changed.as<controls::ScrollViewer>());
                });
        });
    return list;
}

xaml::UIElement UiFactory::ProfilePicture(double size, const media::ImageSource& imageSource) const
{
    if (imageSource != nullptr)
    {
        media::ImageBrush brush;
        brush.ImageSource(imageSource);
        brush.Stretch(media::Stretch::UniformToFill);
        shapes::Ellipse picture;
        picture.Width(size);
        picture.Height(size);
        picture.Fill(brush);
        return picture;
    }

    controls::Grid content;
    content.Width(size);
    content.Height(size);
    shapes::Ellipse circle;
    circle.Width(size);
    circle.Height(size);
    circle.Fill(m_resources.Brush(AppBrush::SecondaryText));
    content.Children().Append(circle);
    auto icon = FluentIcon(Glyphs::Person);
    icon.HorizontalAlignment(xaml::HorizontalAlignment::Center);
    icon.VerticalAlignment(xaml::VerticalAlignment::Center);
    content.Children().Append(icon);
    return content;
}

controls::ListViewItem UiFactory::SectionSpacing() const
{
    controls::ListViewItem spacing;
    spacing.Style(m_resources.Style(AppStyle::SectionSpacing));
    return spacing;
}

shapes::Ellipse UiFactory::StatusDot(bool online) const
{
    shapes::Ellipse dot;
    dot.Style(m_resources.Style(online ? AppStyle::OnlineStatusDot : AppStyle::OfflineStatusDot));
    dot.VerticalAlignment(xaml::VerticalAlignment::Center);
    return dot;
}

controls::TextBlock UiFactory::Text(const winrt::hstring& value, AppStyle style) const
{
    controls::TextBlock block;
    block.Text(value);
    block.Style(m_resources.Style(style));
    return block;
}

controls::Grid UiFactory::ValueWithIconRow(const winrt::hstring& primary,
                                           const winrt::hstring& secondary,
                                           const wchar_t* glyph,
                                           media::Brush iconForeground) const
{
    controls::Grid row;
    auto textColumn = controls::ColumnDefinition();
    textColumn.Width(xaml::GridLengthHelper::FromValueAndType(1, xaml::GridUnitType::Star));
    row.ColumnDefinitions().Append(textColumn);
    auto iconColumn = controls::ColumnDefinition();
    iconColumn.Width(xaml::GridLengthHelper::Auto());
    row.ColumnDefinitions().Append(iconColumn);

    auto text = controls::StackPanel();
    text.Children().Append(Text(primary, AppStyle::TextBody));
    if (!secondary.empty())
    {
        auto secondaryBlock = Text(secondary, AppStyle::TextSecondaryCaption);
        text.Children().Append(secondaryBlock);
    }
    row.Children().Append(text);

    if (glyph != nullptr)
    {
        auto icon = FluentIcon(glyph);
        if (iconForeground != nullptr)
        {
            icon.Foreground(iconForeground);
        }
        icon.VerticalAlignment(xaml::VerticalAlignment::Center);
        icon.Margin(m_resources.Thickness(AppThickness::AccountTextMargin));
        controls::Grid::SetColumn(icon, 1);
        row.Children().Append(icon);
    }
    return row;
}

} // namespace tailgate::uwp
