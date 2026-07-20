#include "app/ui/AppResources.h"

#include <cstdint>
#include <string>

namespace tailgate::uwp
{
namespace
{

constexpr wchar_t ResourceUri[] = L"ms-appx:///TailgateResources.xaml";

const wchar_t* Key(AppBrush resource)
{
    switch (resource)
    {
    case AppBrush::Accent:
        return L"TailgateAccentBrush";
    case AppBrush::Error:
        return L"TailgateErrorBrush";
    case AppBrush::Hover:
        return L"TailgateHoverBrush";
    case AppBrush::OnAccent:
        return L"TailgateOnAccentBrush";
    case AppBrush::OnError:
        return L"TailgateOnErrorBrush";
    case AppBrush::PrimaryText:
        return L"TailgatePrimaryTextBrush";
    case AppBrush::QrBackground:
        return L"TailgateQrBackgroundBrush";
    case AppBrush::QrForeground:
        return L"TailgateQrForegroundBrush";
    case AppBrush::SecondaryText:
        return L"TailgateSecondaryTextBrush";
    case AppBrush::Surface:
        return L"TailgateSurfaceBrush";
    case AppBrush::Transparent:
        return L"TailgateTransparentBrush";
    }
    winrt::terminate();
}

const wchar_t* Key(AppDouble resource)
{
    switch (resource)
    {
    case AppDouble::ChartAxisLabelGap:
        return L"TailgateChartAxisLabelGap";
    case AppDouble::ChartAxisLabelTopOffset:
        return L"TailgateChartAxisLabelTopOffset";
    case AppDouble::ChartDashLength:
        return L"TailgateChartDashLength";
    case AppDouble::ChartHeight:
        return L"TailgateChartHeight";
    case AppDouble::ChartPadBottom:
        return L"TailgateChartPadBottom";
    case AppDouble::ChartPadRight:
        return L"TailgateChartPadRight";
    case AppDouble::ChartPadTop:
        return L"TailgateChartPadTop";
    case AppDouble::ChartPlotLeft:
        return L"TailgateChartPlotLeft";
    case AppDouble::ChartPointDiameter:
        return L"TailgateChartPointDiameter";
    case AppDouble::ChartTickLength:
        return L"TailgateChartTickLength";
    case AppDouble::ChartWidth:
        return L"TailgateChartWidth";
    case AppDouble::ChartXLabelTopGap:
        return L"TailgateChartXLabelTopGap";
    case AppDouble::ChartXLabelWidth:
        return L"TailgateChartXLabelWidth";
    case AppDouble::ChevronFontSize:
        return L"TailgateChevronFontSize";
    case AppDouble::CircleIconContentSize:
        return L"TailgateCircleIconContentSize";
    case AppDouble::ConnectionIconFontSize:
        return L"TailgateConnectionIconFontSize";
    case AppDouble::DevicePingIconSize:
        return L"TailgateDevicePingIconSize";
    case AppDouble::ErrorGlyphFontSize:
        return L"TailgateErrorGlyphFontSize";
    case AppDouble::HomeProgressRingSize:
        return L"TailgateHomeProgressRingSize";
    case AppDouble::ListScrollbarGutter:
        return L"TailgateListScrollbarGutter";
    case AppDouble::NetworkGlyphFontSize:
        return L"TailgateNetworkGlyphFontSize";
    case AppDouble::PingBodyHeight:
        return L"TailgatePingBodyHeight";
    case AppDouble::PingProgressRingSize:
        return L"TailgatePingProgressRingSize";
    case AppDouble::ProfilePictureSize:
        return L"TailgateProfilePictureSize";
    case AppDouble::QrModuleSize:
        return L"TailgateQrModuleSize";
    case AppDouble::SmallProfilePictureSize:
        return L"TailgateSmallProfilePictureSize";
    case AppDouble::StatusDotSize:
        return L"TailgateStatusDotSize";
    case AppDouble::ToggleWidth:
        return L"TailgateToggleWidth";
    }
    winrt::terminate();
}

const wchar_t* Key(AppDataTemplate resource)
{
    switch (resource)
    {
    case AppDataTemplate::DeviceGroupHeader:
        return L"TailgateDeviceGroupHeaderTemplate";
    }
    winrt::terminate();
}

const wchar_t* Key(AppFontWeight resource)
{
    switch (resource)
    {
    case AppFontWeight::Strong:
        return L"TailgateStrongFontWeight";
    }
    winrt::terminate();
}

const wchar_t* Key(AppInteger resource)
{
    switch (resource)
    {
    case AppInteger::ChartGridLineCount:
        return L"TailgateChartGridLineCount";
    }
    winrt::terminate();
}

const wchar_t* Key(AppStyle resource)
{
    switch (resource)
    {
    case AppStyle::AccentCard:
        return L"TailgateAccentCardStyle";
    case AppStyle::ChartAxis:
        return L"TailgateChartAxisStyle";
    case AppStyle::ChartFill:
        return L"TailgateChartFillStyle";
    case AppStyle::ChartGuideline:
        return L"TailgateChartGuidelineStyle";
    case AppStyle::ChartLabel:
        return L"TailgateChartLabelStyle";
    case AppStyle::ChartLine:
        return L"TailgateChartLineStyle";
    case AppStyle::ChartPoint:
        return L"TailgateChartPointStyle";
    case AppStyle::CircleButton:
        return L"TailgateCircleButtonStyle";
    case AppStyle::EmphasizedButton:
        return L"TailgateEmphasizedButtonStyle";
    case AppStyle::EmphasizedErrorButton:
        return L"TailgateEmphasizedErrorButtonStyle";
    case AppStyle::ErrorCard:
        return L"TailgateErrorCardStyle";
    case AppStyle::DeviceGroupHeader:
        return L"TailgateDeviceGroupHeaderStyle";
    case AppStyle::Icon:
        return L"TailgateIconStyle";
    case AppStyle::IconButton:
        return L"TailgateIconButtonStyle";
    case AppStyle::ListHeader:
        return L"TailgateListHeaderStyle";
    case AppStyle::ListHeaderContainer:
        return L"TailgateListHeaderContainerStyle";
    case AppStyle::ListItem:
        return L"TailgateListItemStyle";
    case AppStyle::NeutralCard:
        return L"TailgateNeutralCardStyle";
    case AppStyle::OfflineStatusDot:
        return L"TailgateOfflineStatusDotStyle";
    case AppStyle::OnlineStatusDot:
        return L"TailgateOnlineStatusDotStyle";
    case AppStyle::Page:
        return L"TailgatePageStyle";
    case AppStyle::PingLatency:
        return L"TailgatePingLatencyStyle";
    case AppStyle::PrimaryButton:
        return L"TailgatePrimaryButtonStyle";
    case AppStyle::SectionSpacing:
        return L"TailgateSectionSpacingStyle";
    case AppStyle::TextBody:
        return L"TailgateTextBodyStyle";
    case AppStyle::TextBodyStrong:
        return L"TailgateTextBodyStrongStyle";
    case AppStyle::TextAccentCaption:
        return L"TailgateTextAccentCaptionStyle";
    case AppStyle::TextButton:
        return L"TailgateTextButtonStyle";
    case AppStyle::TextCaption:
        return L"TailgateTextCaptionStyle";
    case AppStyle::TextCaptionStrong:
        return L"TailgateTextCaptionStrongStyle";
    case AppStyle::TextCode:
        return L"TailgateTextCodeStyle";
    case AppStyle::TextDialogTitle:
        return L"TailgateTextDialogTitleStyle";
    case AppStyle::TextErrorBody:
        return L"TailgateTextErrorBodyStyle";
    case AppStyle::TextErrorCaption:
        return L"TailgateTextErrorCaptionStyle";
    case AppStyle::TextErrorSmall:
        return L"TailgateTextErrorSmallStyle";
    case AppStyle::TextErrorStatus:
        return L"TailgateTextErrorStatusStyle";
    case AppStyle::TextErrorSubtitle:
        return L"TailgateTextErrorSubtitleStyle";
    case AppStyle::TextOfflineStatus:
        return L"TailgateTextOfflineStatusStyle";
    case AppStyle::TextNetworkGlyph:
        return L"TailgateNetworkGlyphStyle";
    case AppStyle::TextOnlineStatus:
        return L"TailgateTextOnlineStatusStyle";
    case AppStyle::TextOnEmphasisCaption:
        return L"TailgateTextOnEmphasisCaptionStyle";
    case AppStyle::TextOnEmphasisSubtitle:
        return L"TailgateTextOnEmphasisSubtitleStyle";
    case AppStyle::TextOnErrorCaption:
        return L"TailgateTextOnErrorCaptionStyle";
    case AppStyle::TextOnErrorSubtitle:
        return L"TailgateTextOnErrorSubtitleStyle";
    case AppStyle::TextPageTitle:
        return L"TailgateTextPageTitleStyle";
    case AppStyle::TextSecondaryBody:
        return L"TailgateTextSecondaryBodyStyle";
    case AppStyle::TextSecondaryCaption:
        return L"TailgateTextSecondaryCaptionStyle";
    case AppStyle::TextSecondaryCaptionStrong:
        return L"TailgateTextSecondaryCaptionStrongStyle";
    case AppStyle::TextSecondarySmall:
        return L"TailgateTextSecondarySmallStyle";
    case AppStyle::TextSmall:
        return L"TailgateTextSmallStyle";
    case AppStyle::TextStatus:
        return L"TailgateTextStatusStyle";
    case AppStyle::TextSubtitle:
        return L"TailgateTextSubtitleStyle";
    case AppStyle::TextSubtitleStrong:
        return L"TailgateTextSubtitleStrongStyle";
    case AppStyle::TextTitle:
        return L"TailgateTextTitleStyle";
    case AppStyle::TransparentButton:
        return L"TailgateTransparentButtonStyle";
    }
    winrt::terminate();
}

const wchar_t* Key(AppControlResources resource)
{
    switch (resource)
    {
    case AppControlResources::EmphasizedButton:
        return L"TailgateEmphasizedButtonResources";
    case AppControlResources::EmphasizedErrorButton:
        return L"TailgateEmphasizedErrorButtonResources";
    case AppControlResources::PrimaryButton:
        return L"TailgatePrimaryButtonResources";
    case AppControlResources::TransparentButton:
        return L"TailgateTransparentButtonResources";
    }
    winrt::terminate();
}

const wchar_t* Key(AppItemsPanelTemplate resource)
{
    switch (resource)
    {
    case AppItemsPanelTemplate::StickyDeviceItems:
        return L"TailgateStickyDeviceItemsPanel";
    }
    winrt::terminate();
}

const wchar_t* Key(AppThickness resource)
{
    switch (resource)
    {
    case AppThickness::AccountTextMargin:
        return L"TailgateAccountTextMargin";
    case AppThickness::AdvancedButtonPadding:
        return L"TailgateAdvancedButtonPadding";
    case AppThickness::AdvancedChevronMargin:
        return L"TailgateAdvancedChevronMargin";
    case AppThickness::CardActionMargin:
        return L"TailgateCardActionMargin";
    case AppThickness::CardChevronMargin:
        return L"TailgateCardChevronMargin";
    case AppThickness::CardLabelMargin:
        return L"TailgateCardLabelMargin";
    case AppThickness::CardPickerMargin:
        return L"TailgateCardPickerMargin";
    case AppThickness::CardPickerWithActionMargin:
        return L"TailgateCardPickerWithActionMargin";
    case AppThickness::ConnectedBodyMargin:
        return L"TailgateConnectedBodyMargin";
    case AppThickness::ConnectionRowMargin:
        return L"TailgateConnectionRowMargin";
    case AppThickness::ConnectionTextMargin:
        return L"TailgateConnectionTextMargin";
    case AppThickness::DeviceLabelsMargin:
        return L"TailgateDeviceLabelsMargin";
    case AppThickness::DialogCodeInstructionsMargin:
        return L"TailgateDialogCodeInstructionsMargin";
    case AppThickness::DialogInstructionsMargin:
        return L"TailgateDialogInstructionsMargin";
    case AppThickness::DialogSectionMargin:
        return L"TailgateDialogSectionMargin";
    case AppThickness::DisconnectedDetailMargin:
        return L"TailgateDisconnectedDetailMargin";
    case AppThickness::DisconnectedIconMargin:
        return L"TailgateDisconnectedIconMargin";
    case AppThickness::FieldSpacingMargin:
        return L"TailgateFieldSpacingMargin";
    case AppThickness::HeaderToggleMargin:
        return L"TailgateHeaderToggleMargin";
    case AppThickness::PageTitleMargin:
        return L"TailgatePageTitleMargin";
    case AppThickness::PingBodyMargin:
        return L"TailgatePingBodyMargin";
    case AppThickness::PingErrorTextMargin:
        return L"TailgatePingErrorTextMargin";
    case AppThickness::SearchMargin:
        return L"TailgateSearchMargin";
    case AppThickness::StatusRowMargin:
        return L"TailgateStatusRowMargin";
    case AppThickness::StatusTextMargin:
        return L"TailgateStatusTextMargin";
    case AppThickness::Zero:
        return L"TailgateZeroThickness";
    }
    winrt::terminate();
}

} // namespace

AppResources::AppResources()
{
    try
    {
        m_dictionary.Source(foundation::Uri(ResourceUri));
    }
    catch (const winrt::hresult_error& error)
    {
        m_logger.LogError("unable to load TailgateResources.xaml: {}", error.message());
        throw;
    }
    xaml::Application::Current().Resources().MergedDictionaries().Append(m_dictionary);
}

media::Brush AppResources::Brush(AppBrush resource) const
{
    return Lookup(Key(resource)).as<media::Brush>();
}

xaml::DataTemplate AppResources::DataTemplate(AppDataTemplate resource) const
{
    return Lookup(Key(resource)).as<xaml::DataTemplate>();
}

double AppResources::Double(AppDouble resource) const
{
    return winrt::unbox_value<double>(Lookup(Key(resource)));
}

text::FontWeight AppResources::FontWeight(AppFontWeight resource) const
{
    return winrt::unbox_value<text::FontWeight>(Lookup(Key(resource)));
}

std::int32_t AppResources::Integer(AppInteger resource) const
{
    return winrt::unbox_value<std::int32_t>(Lookup(Key(resource)));
}

controls::ItemsPanelTemplate AppResources::ItemsPanelTemplate(AppItemsPanelTemplate resource) const
{
    return Lookup(Key(resource)).as<controls::ItemsPanelTemplate>();
}

xaml::Style AppResources::Style(AppStyle resource) const
{
    return Lookup(Key(resource)).as<xaml::Style>();
}

xaml::Thickness AppResources::Thickness(AppThickness resource) const
{
    return winrt::unbox_value<xaml::Thickness>(Lookup(Key(resource)));
}

void AppResources::Apply(const xaml::FrameworkElement& element, AppControlResources resources) const
{
    const auto values = Lookup(Key(resources)).as<xaml::ResourceDictionary>();
    for (const auto& value : values)
    {
        element.Resources().Insert(value.Key(), value.Value());
    }
}

foundation::IInspectable AppResources::Lookup(const wchar_t* key) const
{
    return m_dictionary.Lookup(winrt::box_value(key));
}

} // namespace tailgate::uwp
