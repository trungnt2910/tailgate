#include "app/view/impl/PingDialogViewImpl.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <format>
#include <string>
#include <vector>

#include <winrt/Windows.UI.Core.h>

#include "common/ResourceLoader.h"
#include "strings/Resources.h"

#include "app/controller/PingController.h"
#include "app/controller/PingDialogController.h"
#include "app/model/PingDialogState.h"
#include "app/model/PingState.h"
#include "app/ui/AppResources.h"
#include "app/ui/Glyphs.h"
#include "app/ui/UiFactory.h"

namespace tailgate::uwp
{

namespace ui_core = winrt::Windows::UI::Core;

namespace
{

[[nodiscard]] winrt::hstring FormatLatency(double milliseconds, ResourceLoader& resourceLoader)
{
    // Like the Android client's latency label, but latencies of 100 ms and more drop the
    // decimal digit.
    const std::wstring latency = milliseconds < 100 ? std::format(L"{:.1f}", milliseconds)
                                                    : std::format(L"{:.0f}", milliseconds);
    return resourceLoader.Format(Resources::Ping::Milliseconds, std::wstring_view(latency));
}

[[nodiscard]] controls::TextBlock ChartLabel(const winrt::hstring& value, AppResources& resources)
{
    controls::TextBlock label;
    label.Text(value);
    label.Style(resources.Style(AppStyle::ChartLabel));
    return label;
}

[[nodiscard]] shapes::Line ChartLine(double x1,
                                     double y1,
                                     double x2,
                                     double y2,
                                     bool dashed,
                                     AppResources& resources,
                                     AppStyle style)
{
    shapes::Line line;
    line.X1(x1);
    line.Y1(y1);
    line.X2(x2);
    line.Y2(y2);
    line.Style(resources.Style(style));
    if (dashed)
    {
        const double dashLength = resources.Double(AppDouble::ChartDashLength);
        line.StrokeDashArray().Append(dashLength);
        line.StrokeDashArray().Append(dashLength);
    }
    return line;
}

// A simplified take on the Android client's latency chart: y axis in milliseconds with dashed
// guidelines, x axis numbering the pings, a straight line through the samples over a vertical
// accent gradient, and hollow accent data points.
[[nodiscard]] xaml::UIElement BuildPingChart(const std::vector<double>& samples,
                                             AppResources& resources,
                                             ResourceLoader& resourceLoader)
{
    const double chartWidth = resources.Double(AppDouble::ChartWidth);
    const double chartHeight = resources.Double(AppDouble::ChartHeight);
    const double chartPlotLeft = resources.Double(AppDouble::ChartPlotLeft);
    const double chartPadTop = resources.Double(AppDouble::ChartPadTop);
    const double chartPadRight = resources.Double(AppDouble::ChartPadRight);
    const double chartPadBottom = resources.Double(AppDouble::ChartPadBottom);
    const double chartTickLength = resources.Double(AppDouble::ChartTickLength);
    const std::int32_t chartGridLineCount = resources.Integer(AppInteger::ChartGridLineCount);
    controls::Canvas canvas;
    canvas.Width(chartWidth);
    canvas.Height(chartHeight);

    const double plotRight = chartWidth - chartPadRight;
    const double plotBottom = chartHeight - chartPadBottom;
    const double plotWidth = plotRight - chartPlotLeft;
    const double plotHeight = plotBottom - chartPadTop;
    const double maximum = *std::max_element(samples.begin(), samples.end());
    const double axisMaximum = std::max(std::ceil(maximum), 1.0);

    // Horizontal guidelines with y-axis labels, evenly dividing [0, axisMaximum].
    for (std::int32_t index = 0; index < chartGridLineCount; ++index)
    {
        const double fraction =
            static_cast<double>(index) / static_cast<double>(chartGridLineCount - 1);
        const double y = plotBottom - plotHeight * fraction;
        if (index > 0)
        {
            canvas.Children().Append(ChartLine(
                chartPlotLeft, y, plotRight, y, true, resources, AppStyle::ChartGuideline));
        }
        canvas.Children().Append(ChartLine(chartPlotLeft - chartTickLength,
                                           y,
                                           chartPlotLeft,
                                           y,
                                           false,
                                           resources,
                                           AppStyle::ChartAxis));
        const winrt::hstring milliseconds = winrt::to_hstring(std::llround(axisMaximum * fraction));
        auto label = ChartLabel(
            resourceLoader.Format(Resources::Ping::Milliseconds, std::wstring_view(milliseconds)),
            resources);
        label.Width(chartPlotLeft - chartTickLength -
                    resources.Double(AppDouble::ChartAxisLabelGap));
        label.TextAlignment(xaml::TextAlignment::Right);
        controls::Canvas::SetLeft(label, 0);
        controls::Canvas::SetTop(label, y - resources.Double(AppDouble::ChartAxisLabelTopOffset));
        canvas.Children().Append(label);
    }

    // Axis lines and x-axis segment ticks.
    canvas.Children().Append(ChartLine(chartPlotLeft,
                                       chartPadTop,
                                       chartPlotLeft,
                                       plotBottom,
                                       false,
                                       resources,
                                       AppStyle::ChartAxis));
    canvas.Children().Append(ChartLine(
        chartPlotLeft, plotBottom, plotRight, plotBottom, false, resources, AppStyle::ChartAxis));
    const auto count = samples.size();
    for (std::size_t boundary = 0; boundary <= count; ++boundary)
    {
        const double x =
            chartPlotLeft + plotWidth * static_cast<double>(boundary) / static_cast<double>(count);
        canvas.Children().Append(ChartLine(
            x, plotBottom, x, plotBottom + chartTickLength, false, resources, AppStyle::ChartAxis));
    }

    const auto pointX = [&](std::size_t index)
    {
        return chartPlotLeft +
               plotWidth * (static_cast<double>(index) + 0.5) / static_cast<double>(count);
    };
    const auto pointY = [&](double value)
    {
        return plotBottom - plotHeight * (value / axisMaximum);
    };

    // Vertical accent gradient filling the area under the line, like the Android chart.
    if (count >= 2)
    {
        shapes::Polygon fill;
        for (std::size_t index = 0; index < count; ++index)
        {
            fill.Points().Append(foundation::Point{static_cast<float>(pointX(index)),
                                                   static_cast<float>(pointY(samples[index]))});
        }
        fill.Points().Append(foundation::Point{static_cast<float>(pointX(count - 1)),
                                               static_cast<float>(plotBottom)});
        fill.Points().Append(
            foundation::Point{static_cast<float>(pointX(0)), static_cast<float>(plotBottom)});
        fill.Style(resources.Style(AppStyle::ChartFill));
        canvas.Children().Append(fill);

        shapes::Polyline line;
        for (std::size_t index = 0; index < count; ++index)
        {
            line.Points().Append(foundation::Point{static_cast<float>(pointX(index)),
                                                   static_cast<float>(pointY(samples[index]))});
        }
        line.Style(resources.Style(AppStyle::ChartLine));
        canvas.Children().Append(line);
    }

    const double pointDiameter = resources.Double(AppDouble::ChartPointDiameter);
    for (std::size_t index = 0; index < count; ++index)
    {
        shapes::Ellipse point;
        point.Style(resources.Style(AppStyle::ChartPoint));
        controls::Canvas::SetLeft(point, pointX(index) - pointDiameter / 2);
        controls::Canvas::SetTop(point, pointY(samples[index]) - pointDiameter / 2);
        canvas.Children().Append(point);

        auto label = ChartLabel(winrt::to_hstring(index + 1), resources);
        const double labelWidth = resources.Double(AppDouble::ChartXLabelWidth);
        label.Width(labelWidth);
        label.TextAlignment(xaml::TextAlignment::Center);
        controls::Canvas::SetLeft(label, pointX(index) - labelWidth / 2);
        controls::Canvas::SetTop(
            label, plotBottom + chartTickLength + resources.Double(AppDouble::ChartXLabelTopGap));
        canvas.Children().Append(label);
    }

    canvas.HorizontalAlignment(xaml::HorizontalAlignment::Center);
    controls::Viewbox viewport;
    viewport.Child(canvas);
    viewport.Stretch(media::Stretch::Uniform);
    viewport.StretchDirection(controls::StretchDirection::DownOnly);
    viewport.HorizontalAlignment(xaml::HorizontalAlignment::Stretch);
    return viewport;
}

// The "Relayed connection (SYD)" / "Direct connection" row under the dialog title.
[[nodiscard]] xaml::UIElement ConnectionModeRow(bool direct,
                                                const winrt::hstring& relay,
                                                AppResources& resources,
                                                ResourceLoader& resourceLoader,
                                                UiFactory& uiFactory)
{
    auto row = controls::StackPanel();
    row.Orientation(controls::Orientation::Horizontal);
    row.Margin(resources.Thickness(AppThickness::ConnectionRowMargin));
    const auto brush = resources.Brush(direct ? AppBrush::Accent : AppBrush::Error);
    if (direct)
    {
        auto icon = uiFactory.FluentIcon(Glyphs::Forward);
        icon.FontSize(resources.Double(AppDouble::ConnectionIconFontSize));
        icon.Foreground(brush);
        icon.VerticalAlignment(xaml::VerticalAlignment::Center);
        row.Children().Append(icon);
    }
    else
    {
        // No single "broken link" glyph exists in Segoe MDL2; Link and StatusError share the
        // same glyph geometry, so stacking them at the same position and size composes the
        // "broken link" effect (link behind, status mark in front).
        controls::Grid iconStack;
        for (const wchar_t* glyph : {Glyphs::Link, Glyphs::ErrorBadge12})
        {
            auto icon = uiFactory.FluentIcon(glyph);
            icon.FontSize(resources.Double(AppDouble::ConnectionIconFontSize));
            icon.Foreground(brush);
            icon.HorizontalAlignment(xaml::HorizontalAlignment::Center);
            icon.VerticalAlignment(xaml::VerticalAlignment::Center);
            iconStack.Children().Append(icon);
        }
        iconStack.VerticalAlignment(xaml::VerticalAlignment::Center);
        row.Children().Append(iconStack);
    }
    // The relay label arrives display-ready: DERP region codes are uppercased by the plug-in,
    // while Tailgate relay host names keep their lowercase DNS form.
    auto text = uiFactory.Text(direct ? resourceLoader.Get(Resources::Ping::DirectConnection)
                                      : resourceLoader.Format(Resources::Ping::RelayedConnection,
                                                              std::wstring_view(relay)),
                               direct ? AppStyle::TextAccentCaption : AppStyle::TextErrorCaption);
    text.Margin(resources.Thickness(AppThickness::ConnectionTextMargin));
    text.VerticalAlignment(xaml::VerticalAlignment::Center);
    row.Children().Append(text);
    return row;
}

// The centered "Ping failed" body, matching the Android client's error layout.
[[nodiscard]] xaml::UIElement PingErrorPanel(const winrt::hstring& message,
                                             AppResources& resources,
                                             ResourceLoader& resourceLoader,
                                             UiFactory& uiFactory)
{
    auto panel = controls::StackPanel();
    panel.HorizontalAlignment(xaml::HorizontalAlignment::Center);
    panel.VerticalAlignment(xaml::VerticalAlignment::Center);
    auto icon = uiFactory.FluentIcon(Glyphs::Warning);
    icon.FontSize(resources.Double(AppDouble::ErrorGlyphFontSize));
    icon.Foreground(resources.Brush(AppBrush::Error));
    icon.HorizontalAlignment(xaml::HorizontalAlignment::Center);
    panel.Children().Append(icon);
    auto title = uiFactory.Text(resourceLoader.Get(Resources::Ping::PingFailed),
                                AppStyle::TextErrorSubtitle);
    title.HorizontalAlignment(xaml::HorizontalAlignment::Center);
    title.TextAlignment(xaml::TextAlignment::Center);
    title.Margin(resources.Thickness(AppThickness::PingErrorTextMargin));
    panel.Children().Append(title);
    auto detail = uiFactory.Text(message, AppStyle::TextErrorStatus);
    detail.HorizontalAlignment(xaml::HorizontalAlignment::Center);
    detail.TextAlignment(xaml::TextAlignment::Center);
    detail.Margin(resources.Thickness(AppThickness::PingErrorTextMargin));
    panel.Children().Append(detail);
    return panel;
}

// The ring is (re)created every time it is needed: a ProgressRing activated while detached
// from the visual tree (the dialog body before ShowAsync completes) never starts its
// animation, so the dialog swaps in a fresh live one once it has opened.
[[nodiscard]] controls::ProgressRing PingProgressRing(AppResources& resources)
{
    controls::ProgressRing progress;
    progress.Width(resources.Double(AppDouble::PingProgressRingSize));
    progress.Height(resources.Double(AppDouble::PingProgressRingSize));
    progress.HorizontalAlignment(xaml::HorizontalAlignment::Center);
    progress.VerticalAlignment(xaml::VerticalAlignment::Center);
    progress.IsActive(true);
    // Re-activate once the template has loaded; IsActive set before loading can leave the ring
    // invisible on some Windows builds. The toggle back on is dispatched so the deactivation
    // completes a layout pass first - toggling synchronously can still leave the ring's
    // animation stopped.
    progress.Loaded(
        [](const foundation::IInspectable& sender, const auto&)
        {
            const auto ring = sender.as<controls::ProgressRing>();
            ring.IsActive(false);
            ring.Dispatcher().RunAsync(ui_core::CoreDispatcherPriority::Normal,
                                       [ring]
                                       {
                                           ring.IsActive(true);
                                       });
        });
    return progress;
}

} // namespace

PingDialogViewImpl::PingDialogViewImpl(AppResources& resources,
                                       ResourceLoader& resourceLoader,
                                       UiFactory& uiFactory,
                                       PingController& pingController,
                                       PingDialogController& controller)
    : m_state(controller.GetState()),
      m_pingState(pingController.GetState()),
      m_controller(controller),
      m_resources(resources),
      m_resourceLoader(resourceLoader),
      m_uiFactory(uiFactory)
{
    Subscribe(m_state, "dialog");
    Subscribe(m_pingState, "ping");
    Initialize();
}

void PingDialogViewImpl::Render()
{
    // Header mirrors the Android sheet: bold "Pinging <name>" with the connection mode line
    // beneath, and the latest latency top-right in a monospace face.
    controls::Grid header;
    auto titleColumn = controls::ColumnDefinition();
    titleColumn.Width(xaml::GridLengthHelper::FromValueAndType(1, xaml::GridUnitType::Star));
    header.ColumnDefinitions().Append(titleColumn);
    auto latencyColumn = controls::ColumnDefinition();
    latencyColumn.Width(xaml::GridLengthHelper::Auto());
    header.ColumnDefinitions().Append(latencyColumn);

    auto titlePanel = controls::StackPanel();
    m_titleText = m_uiFactory.Text(L"", AppStyle::TextDialogTitle);
    titlePanel.Children().Append(m_titleText);
    m_connectionHost = controls::ContentControl();
    m_connectionHost.IsTabStop(false);
    titlePanel.Children().Append(m_connectionHost);
    header.Children().Append(titlePanel);

    m_latencyText = controls::TextBlock();
    m_latencyText.Style(m_resources.Style(AppStyle::PingLatency));
    m_latencyText.VerticalAlignment(xaml::VerticalAlignment::Top);
    controls::Grid::SetColumn(m_latencyText, 1);
    header.Children().Append(m_latencyText);

    m_body = controls::Grid();
    m_body.Height(m_resources.Double(AppDouble::PingBodyHeight));
    m_body.Margin(m_resources.Thickness(AppThickness::PingBodyMargin));

    auto content = controls::StackPanel();
    content.HorizontalAlignment(xaml::HorizontalAlignment::Stretch);
    content.VerticalAlignment(xaml::VerticalAlignment::Center);
    content.Children().Append(header);
    content.Children().Append(m_body);

    m_dialog = CreateContentDialog();
    m_dialog.Content(content);
    m_dialog.CloseButtonText(m_resourceLoader.Get(Resources::Common::Close));
    // The pre-open ring only sized the body; swap in a fresh one now that the dialog is live in
    // the visual tree, where its animation can actually start.
    m_dialog.Opened(
        [this](const auto&, const auto&)
        {
            if (m_pingState.Status() == PingStatus::Starting &&
                m_state.Error() == PingDialogError::None)
            {
                SetBody(PingProgressRing(m_resources));
            }
        });
}

controls::ContentDialog PingDialogViewImpl::Dialog() const
{
    return m_dialog;
}

void PingDialogViewImpl::OnClosed(controls::ContentDialogResult)
{
    m_controller.OnClosed();
}

void PingDialogViewImpl::OnStateChange(const std::string&)
{
    const PingDialogState& state = m_state;
    m_titleText.Text(
        m_resourceLoader.Format(Resources::Ping::Pinging, std::wstring_view(state.DeviceName())));
    if (state.Error() != PingDialogError::None)
    {
        const winrt::hstring errorMessage =
            state.Error() == PingDialogError::LocalAddress
                ? m_resourceLoader.Format(Resources::Ping::LocalAddress,
                                          std::wstring_view(state.ErrorDetail()))
                : m_resourceLoader.Get(Resources::Error::Unexpected);
        m_latencyText.Text(L"");
        m_connectionHost.Content(nullptr);
        SetBody(PingErrorPanel(errorMessage, m_resources, m_resourceLoader, m_uiFactory));
        return;
    }
    switch (m_pingState.Status())
    {
    case PingStatus::Starting:
        m_latencyText.Text(L"");
        m_connectionHost.Content(nullptr);
        SetBody(PingProgressRing(m_resources));
        return;
    case PingStatus::NoMatchingPeer:
        m_latencyText.Text(L"");
        m_connectionHost.Content(nullptr);
        SetBody(PingErrorPanel(m_resourceLoader.Get(Resources::Ping::NoMatchingPeer),
                               m_resources,
                               m_resourceLoader,
                               m_uiFactory));
        return;
    case PingStatus::Timeout:
        m_latencyText.Text(L"");
        m_connectionHost.Content(nullptr);
        SetBody(PingErrorPanel(m_resourceLoader.Format(Resources::Ping::RequestTimedOut,
                                                       std::wstring_view(state.DeviceName())),
                               m_resources,
                               m_resourceLoader,
                               m_uiFactory));
        return;
    case PingStatus::Failed:
        m_latencyText.Text(L"");
        m_connectionHost.Content(nullptr);
        SetBody(PingErrorPanel(m_resourceLoader.Get(Resources::Error::Unexpected),
                               m_resources,
                               m_resourceLoader,
                               m_uiFactory));
        return;
    case PingStatus::Success:
        break;
    }

    m_latencyText.Text(FormatLatency(m_pingState.LatencyMilliseconds(), m_resourceLoader));
    m_connectionHost.Content(ConnectionModeRow(
        m_pingState.Direct(), m_pingState.Relay(), m_resources, m_resourceLoader, m_uiFactory));
    SetBody(BuildPingChart(m_pingState.Samples(), m_resources, m_resourceLoader));
}

void PingDialogViewImpl::SetBody(const xaml::UIElement& content)
{
    m_body.Children().Clear();
    m_body.Children().Append(content);
}

} // namespace tailgate::uwp
