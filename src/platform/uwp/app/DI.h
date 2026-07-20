#pragma once

#include <memory>

#define BOOST_DI_CFG_CTOR_LIMIT_SIZE 32
#include <boost/di.hpp>

#include "common/ResourceLoader.h"

#include "app/controller/AuthorizationController.h"
#include "app/controller/ClipboardController.h"
#include "app/controller/ContentDialogController.h"
#include "app/controller/ControlPlaneController.h"
#include "app/controller/DevicePageController.h"
#include "app/controller/ExitNodeController.h"
#include "app/controller/HomePageController.h"
#include "app/controller/InteractiveAuthorizationController.h"
#include "app/controller/MainWindowController.h"
#include "app/controller/NavigationController.h"
#include "app/controller/NodeAuthorizationDialogController.h"
#include "app/controller/PackageController.h"
#include "app/controller/PingController.h"
#include "app/controller/PingDialogController.h"
#include "app/controller/ProfilePictureController.h"
#include "app/controller/SessionController.h"
#include "app/controller/SetOptionsController.h"
#include "app/controller/SettingsController.h"
#include "app/controller/SignInDialogController.h"
#include "app/controller/TailgateRelayController.h"
#include "app/controller/VpnProfileController.h"
#include "app/ui/AppResources.h"
#include "app/ui/ButtonFactory.h"
#include "app/ui/UiFactory.h"
#include "app/view/AccountsPageView.h"
#include "app/view/ContentDialogView.h"
#include "app/view/DevicePageView.h"
#include "app/view/ExitNodeControlView.h"
#include "app/view/HomePageView.h"
#include "app/view/MainWindowView.h"
#include "app/view/NavigationPageView.h"
#include "app/view/NodeAuthorizationDialogView.h"
#include "app/view/PingDialogView.h"
#include "app/view/SettingsPageView.h"
#include "app/view/SignInDialogView.h"

namespace tailgate::uwp
{

using AppInjector = boost::di::injector<std::shared_ptr<AuthorizationController>,
                                        std::shared_ptr<AppResources>,
                                        std::shared_ptr<ButtonFactory>,
                                        std::shared_ptr<ClipboardController>,
                                        std::shared_ptr<ControlPlaneController>,
                                        std::shared_ptr<ContentDialogController>,
                                        std::shared_ptr<DevicePageController>,
                                        std::shared_ptr<ExitNodeController>,
                                        std::shared_ptr<HomePageController>,
                                        std::shared_ptr<InteractiveAuthorizationController>,
                                        std::shared_ptr<MainWindowController>,
                                        std::shared_ptr<NavigationController>,
                                        std::shared_ptr<NodeAuthorizationDialogController>,
                                        std::shared_ptr<PackageController>,
                                        std::shared_ptr<PingController>,
                                        std::shared_ptr<PingDialogController>,
                                        std::shared_ptr<ProfilePictureController>,
                                        std::shared_ptr<ResourceLoader>,
                                        std::shared_ptr<SessionController>,
                                        std::shared_ptr<SetOptionsController>,
                                        std::shared_ptr<SignInDialogController>,
                                        std::shared_ptr<SettingsController>,
                                        std::shared_ptr<TailgateRelayController>,
                                        std::shared_ptr<UiFactory>,
                                        std::shared_ptr<VpnProfileController>,
                                        std::unique_ptr<AccountsPageView>,
                                        std::unique_ptr<ContentDialogView>,
                                        std::unique_ptr<DevicePageView>,
                                        std::unique_ptr<ExitNodeControlView>,
                                        std::unique_ptr<HomePageView>,
                                        std::unique_ptr<MainWindowView>,
                                        std::unique_ptr<NavigationPageView>,
                                        std::unique_ptr<NodeAuthorizationDialogView>,
                                        std::unique_ptr<PingDialogView>,
                                        std::unique_ptr<SettingsPageView>,
                                        std::unique_ptr<SignInDialogView>>;

// The function-local instance is initialized on first use. Callers must not resolve dependencies
// from namespace-scope initializers.
[[nodiscard]] AppInjector& GetDI();

} // namespace tailgate::uwp
