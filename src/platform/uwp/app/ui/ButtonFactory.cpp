#include "app/ui/ButtonFactory.h"

namespace tailgate::uwp
{

ButtonFactory::ButtonFactory(AppResources& resources) : m_resources(resources)
{
}

controls::Button ButtonFactory::CircleIcon(const winrt::hstring& glyph,
                                           const winrt::hstring& label,
                                           std::optional<double> iconSize) const
{
    controls::FontIcon icon;
    icon.Glyph(glyph);
    icon.Style(m_resources.Style(AppStyle::Icon));
    if (iconSize)
    {
        icon.FontSize(*iconSize);
    }

    controls::Grid content;
    content.Width(m_resources.Double(AppDouble::CircleIconContentSize));
    content.Height(m_resources.Double(AppDouble::CircleIconContentSize));
    icon.HorizontalAlignment(xaml::HorizontalAlignment::Center);
    icon.VerticalAlignment(xaml::VerticalAlignment::Center);
    content.Children().Append(icon);

    controls::Button button;
    button.Content(content);
    button.Style(m_resources.Style(AppStyle::CircleButton));
    controls::ToolTipService::SetToolTip(button, foundation::PropertyValue::CreateString(label));
    return button;
}

controls::Button ButtonFactory::Icon(const winrt::hstring& glyph, const winrt::hstring& label) const
{
    controls::FontIcon icon;
    icon.Glyph(glyph);
    icon.Style(m_resources.Style(AppStyle::Icon));
    controls::Button button;
    button.Content(icon);
    button.Style(m_resources.Style(AppStyle::IconButton));
    controls::ToolTipService::SetToolTip(button, foundation::PropertyValue::CreateString(label));
    return button;
}

controls::Button ButtonFactory::PrimaryText(const winrt::hstring& value) const
{
    controls::Button button;
    button.Content(foundation::PropertyValue::CreateString(value));
    button.Style(m_resources.Style(AppStyle::PrimaryButton));
    m_resources.Apply(button, AppControlResources::PrimaryButton);
    return button;
}

controls::Button ButtonFactory::Text(const winrt::hstring& value) const
{
    controls::Button button;
    button.Content(foundation::PropertyValue::CreateString(value));
    button.Style(m_resources.Style(AppStyle::TextButton));
    return button;
}

} // namespace tailgate::uwp
