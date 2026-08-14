#pragma once

#include <cstdint>

#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"

#include "common/UwpAliases.h"

namespace tailgate::uwp
{

enum class AppBrush
{
    Accent,
    Error,
    Hover,
    OnAccent,
    OnError,
    PrimaryText,
    QrBackground,
    QrForeground,
    SecondaryText,
    Surface,
    Transparent,
};

enum class AppDouble
{
    ChartDashLength,
    ChartAxisLabelGap,
    ChartAxisLabelTopOffset,
    ChartHeight,
    ChartPadBottom,
    ChartPadRight,
    ChartPadTop,
    ChartPlotLeft,
    ChartPointDiameter,
    ChartTickLength,
    ChartWidth,
    ChartXLabelTopGap,
    ChartXLabelWidth,
    ChevronFontSize,
    CircleIconContentSize,
    ConnectionIconFontSize,
    DevicePingIconSize,
    ErrorGlyphFontSize,
    HomeProgressRingSize,
    ListScrollbarGutter,
    NetworkGlyphFontSize,
    PingBodyHeight,
    PingProgressRingSize,
    ProfilePictureSize,
    QrModuleSize,
    SmallProfilePictureSize,
    StatusDotSize,
    ToggleWidth,
};

enum class AppDataTemplate
{
    DeviceGroupHeader,
};

enum class AppFontWeight
{
    Strong,
};

enum class AppInteger
{
    ChartGridLineCount,
};

enum class AppStyle
{
    AccentCard,
    ChartAxis,
    ChartFill,
    ChartGuideline,
    ChartLabel,
    ChartLine,
    ChartPoint,
    CircleButton,
    EmphasizedButton,
    EmphasizedErrorButton,
    ErrorCard,
    DeviceGroupHeader,
    Icon,
    IconButton,
    ListHeader,
    ListHeaderContainer,
    ListItem,
    NeutralCard,
    OfflineStatusDot,
    OnlineStatusDot,
    Page,
    PingLatency,
    PrimaryButton,
    SectionSpacing,
    TextBody,
    TextBodyStrong,
    TextButton,
    TextCaption,
    TextCaptionStrong,
    TextAccentCaption,
    TextCode,
    TextDialogTitle,
    TextErrorBody,
    TextErrorCaption,
    TextErrorSmall,
    TextErrorStatus,
    TextErrorSubtitle,
    TextOfflineStatus,
    TextNetworkGlyph,
    TextOnlineStatus,
    TextOnEmphasisCaption,
    TextOnEmphasisSubtitle,
    TextOnErrorCaption,
    TextOnErrorSubtitle,
    TextPageTitle,
    TextSecondaryBody,
    TextSecondaryCaption,
    TextSecondaryCaptionStrong,
    TextSecondarySmall,
    TextSmall,
    TextStatus,
    TextSubtitle,
    TextSubtitleStrong,
    TextTitle,
    TransparentButton,
};

enum class AppControlResources
{
    EmphasizedButton,
    EmphasizedErrorButton,
    PrimaryButton,
    TransparentButton,
};

enum class AppItemsPanelTemplate
{
    StickyDeviceItems,
};

enum class AppThickness
{
    AccountTextMargin,
    AdvancedButtonPadding,
    AdvancedChevronMargin,
    CardActionMargin,
    CardChevronMargin,
    CardLabelMargin,
    CardPickerMargin,
    CardPickerWithActionMargin,
    ConnectedBodyMargin,
    ConnectionRowMargin,
    ConnectionTextMargin,
    DeviceLabelsMargin,
    DialogCodeInstructionsMargin,
    DialogInstructionsMargin,
    DialogSectionMargin,
    DisconnectedDetailMargin,
    DisconnectedIconMargin,
    FieldSpacingMargin,
    HeaderToggleMargin,
    PageTitleMargin,
    PingBodyMargin,
    PingErrorTextMargin,
    SearchMargin,
    StatusRowMargin,
    StatusTextMargin,
    Zero,
};

class AppResources final
{
public:
    AppResources();

    [[nodiscard]] media::Brush Brush(AppBrush resource) const;
    [[nodiscard]] xaml::DataTemplate DataTemplate(AppDataTemplate resource) const;
    [[nodiscard]] double Double(AppDouble resource) const;
    [[nodiscard]] text::FontWeight FontWeight(AppFontWeight resource) const;
    [[nodiscard]] std::int32_t Integer(AppInteger resource) const;
    [[nodiscard]] controls::ItemsPanelTemplate
    ItemsPanelTemplate(AppItemsPanelTemplate resource) const;
    [[nodiscard]] xaml::Style Style(AppStyle resource) const;
    [[nodiscard]] xaml::Thickness Thickness(AppThickness resource) const;
    void Apply(const xaml::FrameworkElement& element, AppControlResources resources) const;

private:
    [[nodiscard]] foundation::IInspectable Lookup(const wchar_t* key) const;

    xaml::ResourceDictionary m_dictionary;
    tailgate::base::Logger m_logger{"uwp-app-resources"};
};

} // namespace tailgate::uwp
