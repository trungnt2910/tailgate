#include "app/view/DialogView.h"

#include <algorithm>
#include <cmath>
#include <limits>

#include <winrt/Windows.UI.Core.h>

#include <tailgate/base/Logger.h>

namespace tailgate::uwp
{

namespace ui_core = winrt::Windows::UI::Core;

namespace
{

constexpr wchar_t DialogPresenterName[] = L"BackgroundElement";
constexpr wchar_t DialogScrollViewerName[] = L"ContentScrollViewer";

xaml::FrameworkElement FindDialogElement(const controls::ContentDialog& dialog, const wchar_t* name)
{
    if (media::VisualTreeHelper::GetChildrenCount(dialog) == 0)
    {
        return nullptr;
    }
    const auto templateRoot =
        media::VisualTreeHelper::GetChild(dialog, 0).try_as<xaml::FrameworkElement>();
    if (templateRoot == nullptr)
    {
        return nullptr;
    }
    return templateRoot.FindName(name).try_as<xaml::FrameworkElement>();
}

class ContentDialogImpl : public controls::ContentDialogT<ContentDialogImpl>
{
public:
    ContentDialogImpl()
    {
        const auto maximumWidthKey = winrt::box_value(L"ContentDialogMaxWidth");
        m_platformMaximumWidth = winrt::unbox_value<double>(
            xaml::Application::Current().Resources().Lookup(maximumWidthKey));
    }

    [[nodiscard]] foundation::Size MeasureOverride(const foundation::Size& availableSize)
    {
        const auto dialog = m_inner.as<controls::ContentDialog>();
        ApplyWidth(dialog, xaml::Window::Current().Bounds().Width);
        return m_inner.as<xaml::IFrameworkElementOverrides>().MeasureOverride(availableSize);
    }

    [[nodiscard]] foundation::Size ArrangeOverride(const foundation::Size& finalSize)
    {
        const auto dialog = m_inner.as<controls::ContentDialog>();
        ApplyWidth(dialog, xaml::Window::Current().Bounds().Width);
        CorrectLayout(dialog);
        return m_inner.as<xaml::IFrameworkElementOverrides>().ArrangeOverride(finalSize);
    }

    void OnApplyTemplate()
    {
        m_inner.as<xaml::IFrameworkElementOverrides>().OnApplyTemplate();
        const auto dialog = m_inner.as<controls::ContentDialog>();
        ApplyWidth(dialog, xaml::Window::Current().Bounds().Width);
        ObserveOpened(dialog);
        ObserveWindowSize();
    }

private:
    void ApplyWidth(const controls::ContentDialog& dialog, double windowWidth)
    {
        const double dialogWidth = std::min(m_platformMaximumWidth, windowWidth);
        const auto presenter = FindDialogElement(dialog, DialogPresenterName);
        if (presenter && dialogWidth == m_dialogWidth && presenter.MinWidth() == dialogWidth &&
            presenter.MaxWidth() == dialogWidth)
        {
            return;
        }
        const auto boxedWidth = winrt::box_value(dialogWidth);
        dialog.Resources().Insert(winrt::box_value(L"ContentDialogMinWidth"), boxedWidth);
        dialog.Resources().Insert(winrt::box_value(L"ContentDialogMaxWidth"), boxedWidth);
        if (!presenter)
        {
            m_dialogWidth = std::numeric_limits<double>::quiet_NaN();
            return;
        }
        presenter.MinWidth(dialogWidth);
        presenter.MaxWidth(dialogWidth);
        m_dialogWidth = dialogWidth;
    }

    void ObserveOpened(const controls::ContentDialog& dialog)
    {
        if (m_observingOpened)
        {
            return;
        }
        const auto weakThis = get_weak();
        m_dialogOpened = dialog.Opened(
            [weakThis](const auto&, const auto&)
            {
                if (const auto strongThis = weakThis.get())
                {
                    strongThis->ApplyLayoutCorrection(xaml::Window::Current().Bounds().Width);
                    strongThis->ScheduleLayoutCorrection();
                }
            });
        m_observingOpened = true;
    }

    void ObserveWindowSize()
    {
        if (m_observingWindowSize)
        {
            return;
        }
        m_observingWindowSize = true;
        const auto weakThis = get_weak();
        m_windowSizeChanged = xaml::Window::Current().SizeChanged(
            winrt::auto_revoke,
            [weakThis](const auto&, const auto& arguments)
            {
                if (const auto strongThis = weakThis.get())
                {
                    strongThis->ApplyLayoutCorrection(arguments.Size().Width);
                    strongThis->ScheduleLayoutCorrection();
                }
            });
    }

    void ScheduleLayoutCorrection()
    {
        if (m_layoutCorrectionPending)
        {
            return;
        }
        m_layoutCorrectionPending = true;
        const auto weakThis = get_weak();
        const auto dialog = m_inner.as<controls::ContentDialog>();
        (void)dialog.Dispatcher().RunAsync(ui_core::CoreDispatcherPriority::Low,
                                           [weakThis]
                                           {
                                               if (const auto strongThis = weakThis.get())
                                               {
                                                   strongThis->ApplyPendingLayoutCorrection();
                                               }
                                           });
    }

    void ApplyPendingLayoutCorrection()
    {
        m_layoutCorrectionPending = false;
        ApplyLayoutCorrection(xaml::Window::Current().Bounds().Width);
    }

    void ApplyLayoutCorrection(double windowWidth)
    {
        const auto dialog = m_inner.as<controls::ContentDialog>();
        ApplyWidth(dialog, windowWidth);
        CorrectLayout(dialog);
        dialog.InvalidateMeasure();
        dialog.InvalidateArrange();
    }

    void CorrectLayout(const controls::ContentDialog& dialog)
    {
        bool alignmentCorrected = false;
        bool heightCorrected = false;
        if (const auto presenter = FindDialogElement(dialog, DialogPresenterName);
            presenter && presenter.VerticalAlignment() != xaml::VerticalAlignment::Center)
        {
            presenter.VerticalAlignment(xaml::VerticalAlignment::Center);
            alignmentCorrected = true;
        }
        const auto scrollViewer =
            FindDialogElement(dialog, DialogScrollViewerName).try_as<controls::ScrollViewer>();
        if (scrollViewer && !std::isnan(scrollViewer.Height()))
        {
            scrollViewer.Height(std::numeric_limits<double>::quiet_NaN());
            heightCorrected = true;
        }
        if (alignmentCorrected || heightCorrected)
        {
            m_logger.LogTrace("corrected content dialog layout alignment={} height={}",
                              alignmentCorrected,
                              heightCorrected);
        }
    }

    tailgate::base::Logger m_logger{"uwp-content-dialog"};
    xaml::IWindow::SizeChanged_revoker m_windowSizeChanged;
    winrt::event_token m_dialogOpened{};
    double m_platformMaximumWidth = 0;
    double m_dialogWidth = std::numeric_limits<double>::quiet_NaN();
    bool m_layoutCorrectionPending = false;
    bool m_observingOpened = false;
    bool m_observingWindowSize = false;
};

} // namespace

controls::ContentDialog DialogView::CreateContentDialog()
{
    return winrt::make_self<ContentDialogImpl>().as<controls::ContentDialog>();
}

} // namespace tailgate::uwp
