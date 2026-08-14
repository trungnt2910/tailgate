#pragma once

#include <optional>
#include <string_view>

#include <tailgate/base/Logger.h>

#include "common/UwpAliases.h"
#include "common/UwpFireAndForget.h"
#include "common/UwpFormat.h"

#include "app/controller/VpnProfileController.h"

namespace tailgate::uwp
{

class VpnProfileControllerImpl final : public VpnProfileController
{
public:
    [[nodiscard]] const VpnProfileState& GetState() const noexcept override;
    void Connect(winrt::hstring tailgateServer,
                 winrt::hstring authKey,
                 bool restartConnectedProfile) override;
    void CancelConnect() override;
    void Disconnect() override;
    void Logout() override;
    void DiscardProfile() override;
    void Refresh() override;

private:
    [[nodiscard]] bool Begin(VpnProfileActivity activity, std::string_view operation);
    void Complete(std::optional<UwpError::Code> error,
                  std::optional<bool> connected = std::nullopt);
    [[nodiscard]] std::optional<vpn::VpnManagementConnectionStatus>
    ConnectionStatusOrUnavailable(const vpn::VpnPlugInProfile& profile, std::string_view operation);
    [[nodiscard]] foundation::IAsyncAction RemoveProfileAsync(const vpn::VpnPlugInProfile& profile,
                                                              std::string_view operation);
    [[nodiscard]] foundation::IAsyncOperation<vpn::VpnPlugInProfile> FindProfileAsync();
    [[nodiscard]] foundation::IAsyncOperation<vpn::VpnPlugInProfile>
    EnsureProfileAsync(winrt::hstring tailgateServer, winrt::hstring authKey, bool& newlyAdded);
    FireAndForget ConnectInBackground(winrt::hstring tailgateServer,
                                      winrt::hstring authKey,
                                      bool restartConnectedProfile);
    FireAndForget DisconnectInBackground();
    FireAndForget LogoutInBackground();
    FireAndForget DiscardProfileInBackground();
    FireAndForget RefreshInBackground();

    vpn::VpnManagementAgent m_agent;
    vpn::VpnPlugInProfile m_newlyAddedProfile{nullptr};
    foundation::IAsyncOperation<vpn::VpnManagementErrorStatus> m_connectOperation{nullptr};
    VpnProfileState m_state;
    tailgate::base::Logger m_logger{"uwp-vpn-profile-ctrl"};
};

} // namespace tailgate::uwp
