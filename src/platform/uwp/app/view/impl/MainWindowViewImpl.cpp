#include "app/view/impl/MainWindowViewImpl.h"

#include <utility>

#include <winrt/Windows.UI.Core.h>

#include "app/controller/MainWindowController.h"
#include "app/controller/NavigationController.h"
#include "app/view/ContentDialogView.h"
#include "app/view/NavigationPageView.h"

namespace tailgate::uwp
{

namespace core_input = winrt::Windows::UI::Core;

MainWindowViewImpl::MainWindowViewImpl(MainWindowController& controller,
                                       NavigationController& navigationController,
                                       std::unique_ptr<ContentDialogView> contentDialogView,
                                       std::unique_ptr<NavigationPageView> navigationPageView)
    : m_controller(controller),
      m_navigationController(navigationController),
      m_contentDialogView(std::move(contentDialogView)),
      m_navigationPageView(std::move(navigationPageView))
{
    Subscribe(m_navigationController.GetState(), "navigation");
    Initialize();
}

void MainWindowViewImpl::Render()
{
    core_input::SystemNavigationManager::GetForCurrentView().BackRequested(
        [this](const auto&, const core_input::BackRequestedEventArgs& args)
        {
            if (m_navigationController.GetState().CanGoBack())
            {
                args.Handled(true);
                m_navigationController.Back();
            }
        });
}

void MainWindowViewImpl::Show()
{
    auto window = xaml::Window::Current();
    window.Content(m_navigationPageView->Page());
    OnStateChange("");
    window.Activate();
    m_controller.Activate();
}

void MainWindowViewImpl::OnStateChange(const std::string&)
{
    core_input::SystemNavigationManager::GetForCurrentView().AppViewBackButtonVisibility(
        m_navigationController.GetState().CanGoBack()
            ? core_input::AppViewBackButtonVisibility::Visible
            : core_input::AppViewBackButtonVisibility::Collapsed);
}

} // namespace tailgate::uwp
