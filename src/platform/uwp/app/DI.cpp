#include "app/DI.h"

#include "app/controller/impl/AuthorizationControllerImpl.h"
#include "app/controller/impl/ClipboardControllerImpl.h"
#include "app/controller/impl/ContentDialogControllerImpl.h"
#include "app/controller/impl/ControlPlaneControllerImpl.h"
#include "app/controller/impl/DevicePageControllerImpl.h"
#include "app/controller/impl/ExitNodeControllerImpl.h"
#include "app/controller/impl/HomePageControllerImpl.h"
#include "app/controller/impl/InteractiveAuthorizationControllerImpl.h"
#include "app/controller/impl/MainWindowControllerImpl.h"
#include "app/controller/impl/NavigationControllerImpl.h"
#include "app/controller/impl/NodeAuthorizationDialogControllerImpl.h"
#include "app/controller/impl/PackageControllerImpl.h"
#include "app/controller/impl/PingControllerImpl.h"
#include "app/controller/impl/PingDialogControllerImpl.h"
#include "app/controller/impl/ProfilePictureControllerImpl.h"
#include "app/controller/impl/SessionControllerImpl.h"
#include "app/controller/impl/SetOptionsControllerImpl.h"
#include "app/controller/impl/SettingsControllerImpl.h"
#include "app/controller/impl/SignInDialogControllerImpl.h"
#include "app/controller/impl/TailgateRelayControllerImpl.h"
#include "app/controller/impl/VpnProfileControllerImpl.h"
#include "app/ui/ResourceLoader.h"
#include "app/view/impl/AccountsPageViewImpl.h"
#include "app/view/impl/ContentDialogViewImpl.h"
#include "app/view/impl/DevicePageViewImpl.h"
#include "app/view/impl/ExitNodeControlViewImpl.h"
#include "app/view/impl/HomePageViewImpl.h"
#include "app/view/impl/MainWindowViewImpl.h"
#include "app/view/impl/NavigationPageViewImpl.h"
#include "app/view/impl/NodeAuthorizationDialogViewImpl.h"
#include "app/view/impl/PingDialogViewImpl.h"
#include "app/view/impl/SettingsPageViewImpl.h"
#include "app/view/impl/SignInDialogViewImpl.h"

namespace tailgate::uwp
{
namespace di = boost::di;

AppInjector& GetDI()
{
    static AppInjector injector = di::make_injector(
        // Application UI
        di::bind<ResourceLoader>.to<app::ResourceLoader>().in(di::singleton),
        di::bind<AppResources>.in(di::singleton),
        di::bind<ButtonFactory>.in(di::singleton),
        di::bind<UiFactory>.in(di::singleton),

        // System Feature Controllers
        di::bind<ClipboardController>.to<ClipboardControllerImpl>().in(di::singleton),
        di::bind<ControlPlaneController>.to<ControlPlaneControllerImpl>().in(di::singleton),
        di::bind<InteractiveAuthorizationController>.to<InteractiveAuthorizationControllerImpl>().in(
            di::singleton),
        di::bind<NodeAuthorizationDialogController>.to<NodeAuthorizationDialogControllerImpl>().in(
            di::singleton),
        di::bind<PingController>.to<PingControllerImpl>().in(di::singleton),
        di::bind<PackageController>.to<PackageControllerImpl>().in(di::singleton),
        di::bind<SettingsController>.to<SettingsControllerImpl>().in(di::singleton),
        di::bind<TailgateRelayController>.to<TailgateRelayControllerImpl>().in(di::singleton),
        di::bind<VpnProfileController>.to<VpnProfileControllerImpl>().in(di::singleton),

        // Logical UI Controllers
        di::bind<AuthorizationController>.to<AuthorizationControllerImpl>().in(di::singleton),
        di::bind<ContentDialogController>.to<ContentDialogControllerImpl>().in(di::singleton),
        di::bind<DevicePageController>.to<DevicePageControllerImpl>().in(di::singleton),
        di::bind<ExitNodeController>.to<ExitNodeControllerImpl>().in(di::singleton),
        di::bind<HomePageController>.to<HomePageControllerImpl>().in(di::singleton),
        di::bind<MainWindowController>.to<MainWindowControllerImpl>().in(di::singleton),
        di::bind<NavigationController>.to<NavigationControllerImpl>().in(di::singleton),
        di::bind<PingDialogController>.to<PingDialogControllerImpl>().in(di::singleton),
        di::bind<ProfilePictureController>.to<ProfilePictureControllerImpl>().in(di::singleton),
        di::bind<SessionController>.to<SessionControllerImpl>().in(di::singleton),
        di::bind<SetOptionsController>.to<SetOptionsControllerImpl>().in(di::singleton),
        di::bind<SignInDialogController>.to<SignInDialogControllerImpl>().in(di::singleton),

        // Views
        di::bind<AccountsPageView>.to<AccountsPageViewImpl>().in(di::unique),
        di::bind<ContentDialogView>.to<ContentDialogViewImpl>().in(di::unique),
        di::bind<DevicePageView>.to<DevicePageViewImpl>().in(di::unique),
        di::bind<ExitNodeControlView>.to<ExitNodeControlViewImpl>().in(di::unique),
        di::bind<HomePageView>.to<HomePageViewImpl>().in(di::unique),
        di::bind<MainWindowView>.to<MainWindowViewImpl>().in(di::unique),
        di::bind<NavigationPageView>.to<NavigationPageViewImpl>().in(di::unique),
        di::bind<NodeAuthorizationDialogView>.to<NodeAuthorizationDialogViewImpl>().in(di::unique),
        di::bind<PingDialogView>.to<PingDialogViewImpl>().in(di::unique),
        di::bind<SettingsPageView>.to<SettingsPageViewImpl>().in(di::unique),
        di::bind<SignInDialogView>.to<SignInDialogViewImpl>().in(di::unique));
    return injector;
}

} // namespace tailgate::uwp
