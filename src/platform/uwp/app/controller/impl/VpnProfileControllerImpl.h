#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

#include <winrt/Windows.ApplicationModel.Core.h>
#include <winrt/Windows.Networking.Connectivity.h>
#include <winrt/Windows.Storage.h>

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
    ~VpnProfileControllerImpl() override;
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
    void EnsureStatusWatchStarted();
    [[nodiscard]] bool Begin(VpnProfileActivity activity, std::string_view operation);
    void Complete(std::optional<UwpError::Code> error,
                  std::optional<bool> connected = std::nullopt);
    [[nodiscard]] std::optional<vpn::VpnManagementConnectionStatus>
    ConnectionStatusOrUnavailable(const vpn::VpnPlugInProfile& profile, std::string_view operation);
    [[nodiscard]] foundation::IAsyncAction RemoveProfileAsync(const vpn::VpnPlugInProfile& profile,
                                                              std::string_view operation);
    [[nodiscard]] foundation::IAsyncOperation<vpn::VpnPlugInProfile> FindProfileAsync();
    [[nodiscard]] foundation::IAsyncOperation<vpn::VpnManagementErrorStatus>
    DisconnectAndWaitAsync(vpn::VpnPlugInProfile profile);
    [[nodiscard]] foundation::IAsyncOperation<vpn::VpnManagementErrorStatus>
    DialProfileAsync(vpn::VpnPlugInProfile profile, std::size_t& activationRetries);
    [[nodiscard]] foundation::IAsyncOperation<vpn::VpnManagementErrorStatus>
    ConnectProfileAsync(vpn::VpnPlugInProfile& profile,
                        bool afterDisconnect,
                        winrt::hstring tailgateServer,
                        winrt::hstring authKey);
    [[nodiscard]] foundation::IAsyncOperation<vpn::VpnPlugInProfile>
    EnsureProfileAsync(winrt::hstring tailgateServer, winrt::hstring authKey, bool& newlyAdded);
    FireAndForget ConnectInBackground(winrt::hstring tailgateServer,
                                      winrt::hstring authKey,
                                      bool restartConnectedProfile);
    FireAndForget DisconnectInBackground();
    FireAndForget LogoutInBackground();
    FireAndForget DiscardProfileInBackground();
    foundation::IAsyncAction RefreshInBackground();

    // The controller and its queued callbacks are owned by the UI thread.
    struct StatusWatch
    {
        VpnProfileControllerImpl& Controller;
    };

    std::shared_ptr<StatusWatch> m_statusWatch;
    winrt::Windows::Networking::Connectivity::NetworkInformation::NetworkStatusChanged_revoker
        m_networkChanged;
    winrt::Windows::ApplicationModel::Core::CoreApplication::Resuming_revoker m_resuming;
    winrt::Windows::Storage::ApplicationData::DataChanged_revoker m_dataChanged;
    bool m_statusWatchStarted = false;
    bool m_refreshPending = false;
    std::atomic_bool m_connectCancelled = false;
    std::uint64_t m_operationGeneration = 0;
    vpn::VpnManagementAgent m_agent;
    vpn::VpnPlugInProfile m_newlyAddedProfile{nullptr};
    foundation::IAsyncOperation<vpn::VpnManagementErrorStatus> m_connectOperation{nullptr};
    foundation::IAsyncAction m_refreshOperation{nullptr};
    VpnProfileState m_state;
    tailgate::base::Logger m_logger{"uwp-vpn-profile-ctrl"};
};

} // namespace tailgate::uwp
