#include "app/controller/impl/VpnProfileControllerImpl.h"

#include <cstdint>
#include <exception>
#include <format>
#include <string>
#include <string_view>

#include <windows.h>

#include "common/VpnConstants.h"

namespace tailgate::uwp
{

namespace
{

template <typename Status>
std::string StatusValue(Status status)
{
    return std::format("{}", static_cast<std::int32_t>(status));
}

UwpError::Code ErrorCodeOr(winrt::hresult result, UwpError::Code fallback)
{
    return UwpError::FromHresult(result).value_or(fallback);
}

} // namespace

const VpnProfileState& VpnProfileControllerImpl::GetState() const noexcept
{
    return m_state;
}

bool VpnProfileControllerImpl::Begin(VpnProfileActivity activity, std::string_view operation)
{
    if (m_state.Busy())
    {
        m_logger.LogDebug("ignoring {}: VPN profile operation is active", operation);
        return false;
    }
    m_state.Update(
        [&](VpnProfileState& state)
        {
            state.Activity(activity);
            state.Busy(true);
            state.Error(std::nullopt);
        });
    return true;
}

void VpnProfileControllerImpl::Complete(std::optional<UwpError::Code> error,
                                        std::optional<bool> connected)
{
    m_connectOperation = nullptr;
    m_state.Update(
        [&](VpnProfileState& state)
        {
            if (connected)
            {
                state.Connected(*connected);
            }
            state.Error(error);
            state.Busy(false);
        });
}

void VpnProfileControllerImpl::Connect(winrt::hstring tailgateServer,
                                       winrt::hstring authKey,
                                       bool restartConnectedProfile)
{
    if (Begin(VpnProfileActivity::Connecting, "connect"))
    {
        (void)ConnectInBackground(
            std::move(tailgateServer), std::move(authKey), restartConnectedProfile);
    }
}

void VpnProfileControllerImpl::CancelConnect()
{
    if (m_state.Busy() && m_state.Activity() == VpnProfileActivity::Connecting &&
        m_connectOperation)
    {
        m_connectOperation.Cancel();
    }
}

void VpnProfileControllerImpl::Disconnect()
{
    if (Begin(VpnProfileActivity::Disconnecting, "disconnect"))
    {
        (void)DisconnectInBackground();
    }
}

void VpnProfileControllerImpl::Logout()
{
    if (Begin(VpnProfileActivity::LoggingOut, "logout"))
    {
        (void)LogoutInBackground();
    }
}

void VpnProfileControllerImpl::DiscardProfile()
{
    if (Begin(VpnProfileActivity::Discarding, "discard profile"))
    {
        (void)DiscardProfileInBackground();
    }
}

void VpnProfileControllerImpl::Refresh()
{
    if (Begin(VpnProfileActivity::Refreshing, "refresh"))
    {
        (void)RefreshInBackground();
    }
}

std::optional<vpn::VpnManagementConnectionStatus>
VpnProfileControllerImpl::ConnectionStatusOrUnavailable(const vpn::VpnPlugInProfile& profile,
                                                        std::string_view operation)
{
    try
    {
        return profile.ConnectionStatus();
    }
    catch (const winrt::hresult_error& error)
    {
        if (error.code() != E_HANDLE)
        {
            throw;
        }
        m_logger.LogDebug("VPN profile connection status is unavailable operation={}", operation);
        return std::nullopt;
    }
}

foundation::IAsyncAction
VpnProfileControllerImpl::RemoveProfileAsync(const vpn::VpnPlugInProfile& profile,
                                             std::string_view operation)
{
    const auto status = co_await m_agent.DeleteProfileAsync(profile);
    const bool accepted = status == vpn::VpnManagementErrorStatus::Ok ||
                          status == vpn::VpnManagementErrorStatus::CannotFindProfile;
    if (accepted)
    {
        m_logger.LogDebug(
            "delete VPN profile operation={} status={}", operation, StatusValue(status));
        co_return;
    }
    m_logger.LogError("delete VPN profile operation={} status={}", operation, StatusValue(status));
    UwpError::Throw(UwpError::Code::VpnProfileOperationFailed);
}

foundation::IAsyncOperation<vpn::VpnPlugInProfile> VpnProfileControllerImpl::FindProfileAsync()
{
    const auto profiles = co_await m_agent.GetProfilesAsync();
    for (const auto& profile : profiles)
    {
        auto pluginProfile = profile.try_as<vpn::VpnPlugInProfile>();
        if (pluginProfile && pluginProfile.ProfileName() == VpnConstants::Product::Name)
        {
            co_return pluginProfile;
        }
    }
    co_return nullptr;
}

foundation::IAsyncOperation<vpn::VpnPlugInProfile> VpnProfileControllerImpl::EnsureProfileAsync(
    winrt::hstring tailgateServer, winrt::hstring authKey, bool& newlyAdded)
{
    newlyAdded = false;
    auto settings = storage::ApplicationData::Current().LocalSettings().Values();
    settings.Insert(L"TailgateServer", winrt::box_value(tailgateServer));
    if (!authKey.empty())
    {
        settings.Insert(L"AuthKey", winrt::box_value(authKey));
    }

    auto existing = co_await FindProfileAsync();
    if (existing)
    {
        const std::optional<vpn::VpnManagementConnectionStatus> status =
            ConnectionStatusOrUnavailable(existing, "ensure-profile");
        if (status)
        {
            m_logger.LogDebug("existing profile status={}", StatusValue(*status));
            co_return existing;
        }

        m_logger.LogInfo("replacing VPN profile with an invalid connection handle");
        co_await RemoveProfileAsync(existing, "replace-invalid-handle");
        m_agent = vpn::VpnManagementAgent();
    }

    m_logger.LogInfo("adding VPN profile");
    vpn::VpnPlugInProfile profile;
    profile.ProfileName(VpnConstants::Product::Name);
    profile.RequireVpnClientAppUI(true);
    profile.VpnPluginPackageFamilyName(appmodel::Package::Current().Id().FamilyName());
    profile.ServerUris().Append(foundation::Uri(tailgateServer));
    const std::wstring configuration =
        std::format(L"<tailgate><server>{}</server><authKeyPresent>{}</authKeyPresent></tailgate>",
                    tailgateServer.c_str(),
                    !authKey.empty());
    profile.CustomConfiguration(winrt::hstring(configuration));
    const auto addStatus = co_await m_agent.AddProfileFromObjectAsync(profile);
    if (addStatus != vpn::VpnManagementErrorStatus::Ok)
    {
        m_logger.LogError("add profile status={}", StatusValue(addStatus));
        UwpError::Throw(UwpError::Code::VpnProfileOperationFailed);
    }
    m_logger.LogDebug("add profile status={}", StatusValue(addStatus));
    newlyAdded = true;
    m_newlyAddedProfile = profile;
    co_return profile;
}

FireAndForget VpnProfileControllerImpl::ConnectInBackground(winrt::hstring tailgateServer,
                                                            winrt::hstring authKey,
                                                            bool restartConnectedProfile)
{
    winrt::apartment_context uiThread;
    bool connected = false;
    std::optional<UwpError::Code> failure;
    try
    {
        bool newlyAdded = false;
        vpn::VpnPlugInProfile profile{nullptr};
        if (m_newlyAddedProfile)
        {
            profile = m_newlyAddedProfile;
            newlyAdded = true;
            m_logger.LogDebug("reusing newly added VPN profile for authorization retry");
        }
        else
        {
            profile = co_await EnsureProfileAsync(tailgateServer, authKey, newlyAdded);
        }
        if (!newlyAdded)
        {
            const std::optional<vpn::VpnManagementConnectionStatus> status =
                ConnectionStatusOrUnavailable(profile, "connect");
            if (status == vpn::VpnManagementConnectionStatus::Connected && !restartConnectedProfile)
            {
                connected = true;
            }
            else if (status && *status != vpn::VpnManagementConnectionStatus::Disconnected)
            {
                m_logger.LogInfo("disconnecting VPN profile before connect");
                const auto disconnectStatus = co_await m_agent.DisconnectProfileAsync(profile);
                if (disconnectStatus != vpn::VpnManagementErrorStatus::Ok &&
                    disconnectStatus != vpn::VpnManagementErrorStatus::AlreadyDisconnecting &&
                    disconnectStatus != vpn::VpnManagementErrorStatus::NoConnection)
                {
                    UwpError::Throw(UwpError::Code::VpnProfileOperationFailed);
                }
            }
        }
        if (!connected)
        {
            m_logger.LogInfo("connecting VPN profile");
            m_connectOperation = m_agent.ConnectProfileAsync(profile);
            const auto status = co_await m_connectOperation;
            const bool accepted = status == vpn::VpnManagementErrorStatus::Ok ||
                                  status == vpn::VpnManagementErrorStatus::AlreadyConnected;
            if (!accepted)
            {
                m_logger.LogError("connect profile status={}", StatusValue(status));
                UwpError::Throw(UwpError::Code::VpnProfileOperationFailed);
            }
            m_logger.LogDebug("connect profile status={}", StatusValue(status));
        }
        const std::optional<vpn::VpnManagementConnectionStatus> finalStatus =
            ConnectionStatusOrUnavailable(profile, "after-connect");
        connected = finalStatus == vpn::VpnManagementConnectionStatus::Connected;
        if (!connected)
        {
            failure = UwpError::Code::VpnProfileDidNotConnect;
        }
        else
        {
            m_newlyAddedProfile = nullptr;
        }
    }
    catch (const winrt::hresult_canceled&)
    {
        failure = UwpError::Code::ConnectionCancelled;
    }
    catch (const winrt::hresult_error& error)
    {
        failure = ErrorCodeOr(error.code(), UwpError::Code::VpnProfileOperationFailed);
        m_logger.LogError("connect failed hresult={} message={}", error.code(), error.message());
    }
    catch (const std::exception& error)
    {
        failure = UwpError::Code::VpnProfileOperationFailed;
        m_logger.LogError("connect failed: {}", error.what());
    }

    if (!connected)
    {
        try
        {
            auto profile = co_await FindProfileAsync();
            if (profile)
            {
                const auto status = co_await m_agent.DisconnectProfileAsync(profile);
                if (status != vpn::VpnManagementErrorStatus::Ok &&
                    status != vpn::VpnManagementErrorStatus::AlreadyDisconnecting &&
                    status != vpn::VpnManagementErrorStatus::NoConnection)
                {
                    m_logger.LogWarning("connect cleanup disconnect status={}",
                                        StatusValue(status));
                }
            }
        }
        catch (const winrt::hresult_error& error)
        {
            m_logger.LogWarning("connect cleanup disconnect failed: {}", error.message());
        }
        catch (const std::exception& error)
        {
            m_logger.LogWarning("connect cleanup disconnect failed: {}", error.what());
        }
    }
    co_await uiThread;
    Complete(failure, connected);
}

FireAndForget VpnProfileControllerImpl::DisconnectInBackground()
{
    winrt::apartment_context uiThread;
    std::optional<UwpError::Code> failure;
    try
    {
        auto profile = co_await FindProfileAsync();
        if (profile)
        {
            const auto status = co_await m_agent.DisconnectProfileAsync(profile);
            const bool accepted = status == vpn::VpnManagementErrorStatus::Ok ||
                                  status == vpn::VpnManagementErrorStatus::AlreadyDisconnecting ||
                                  status == vpn::VpnManagementErrorStatus::NoConnection;
            if (!accepted)
            {
                UwpError::Throw(UwpError::Code::VpnDisconnectFailed);
            }
            m_logger.LogDebug("disconnect profile status={}", StatusValue(status));
        }
    }
    catch (const winrt::hresult_error& error)
    {
        failure = ErrorCodeOr(error.code(), UwpError::Code::VpnDisconnectFailed);
        m_logger.LogError("disconnect failed hresult={} message={}", error.code(), error.message());
    }
    catch (const std::exception& error)
    {
        failure = UwpError::Code::VpnDisconnectFailed;
        m_logger.LogError("disconnect failed: {}", error.what());
    }
    co_await uiThread;
    Complete(failure, failure ? std::nullopt : std::optional(false));
}

FireAndForget VpnProfileControllerImpl::LogoutInBackground()
{
    winrt::apartment_context uiThread;
    std::optional<UwpError::Code> failure;
    try
    {
        auto profile = co_await FindProfileAsync();
        if (profile)
        {
            const std::optional<vpn::VpnManagementConnectionStatus> connectionStatus =
                ConnectionStatusOrUnavailable(profile, "logout");
            if (connectionStatus &&
                *connectionStatus != vpn::VpnManagementConnectionStatus::Disconnected)
            {
                const auto status = co_await m_agent.DisconnectProfileAsync(profile);
                if (status != vpn::VpnManagementErrorStatus::Ok &&
                    status != vpn::VpnManagementErrorStatus::AlreadyDisconnecting &&
                    status != vpn::VpnManagementErrorStatus::NoConnection)
                {
                    UwpError::Throw(UwpError::Code::VpnLogoutFailed);
                }
            }
            co_await RemoveProfileAsync(profile, "logout");
        }
    }
    catch (const winrt::hresult_error& error)
    {
        failure = ErrorCodeOr(error.code(), UwpError::Code::VpnLogoutFailed);
        m_logger.LogError("logout failed hresult={} message={}", error.code(), error.message());
    }
    catch (const std::exception& error)
    {
        failure = UwpError::Code::VpnLogoutFailed;
        m_logger.LogError("logout failed: {}", error.what());
    }
    co_await uiThread;
    Complete(failure, failure ? std::nullopt : std::optional(false));
}

FireAndForget VpnProfileControllerImpl::DiscardProfileInBackground()
{
    winrt::apartment_context uiThread;
    std::optional<UwpError::Code> failure;
    try
    {
        vpn::VpnPlugInProfile profile{nullptr};
        if (m_newlyAddedProfile)
        {
            profile = m_newlyAddedProfile;
            m_newlyAddedProfile = nullptr;
        }
        else
        {
            profile = co_await FindProfileAsync();
        }
        if (profile)
        {
            const std::optional<vpn::VpnManagementConnectionStatus> connectionStatus =
                ConnectionStatusOrUnavailable(profile, "discard-profile");
            if (connectionStatus &&
                *connectionStatus != vpn::VpnManagementConnectionStatus::Disconnected)
            {
                const auto status = co_await m_agent.DisconnectProfileAsync(profile);
                if (status != vpn::VpnManagementErrorStatus::Ok &&
                    status != vpn::VpnManagementErrorStatus::AlreadyDisconnecting &&
                    status != vpn::VpnManagementErrorStatus::NoConnection)
                {
                    UwpError::Throw(UwpError::Code::VpnProfileOperationFailed);
                }
            }
            co_await RemoveProfileAsync(profile, "discard");
        }
    }
    catch (const winrt::hresult_error& error)
    {
        failure = ErrorCodeOr(error.code(), UwpError::Code::VpnProfileOperationFailed);
        m_logger.LogWarning("discard failed hresult={} message={}", error.code(), error.message());
    }
    catch (const std::exception& error)
    {
        failure = UwpError::Code::VpnProfileOperationFailed;
        m_logger.LogWarning("discard failed: {}", error.what());
    }
    co_await uiThread;
    Complete(failure, failure ? std::nullopt : std::optional(false));
}

FireAndForget VpnProfileControllerImpl::RefreshInBackground()
{
    winrt::apartment_context uiThread;
    bool connected = false;
    std::optional<UwpError::Code> failure;
    try
    {
        auto profile = co_await FindProfileAsync();
        if (profile)
        {
            const std::optional<vpn::VpnManagementConnectionStatus> status =
                ConnectionStatusOrUnavailable(profile, "refresh");
            connected = status == vpn::VpnManagementConnectionStatus::Connected;
        }
    }
    catch (const winrt::hresult_error& error)
    {
        failure = ErrorCodeOr(error.code(), UwpError::Code::VpnProfileOperationFailed);
        m_logger.LogWarning("refresh failed hresult={} message={}", error.code(), error.message());
    }
    catch (const std::exception& error)
    {
        failure = UwpError::Code::VpnProfileOperationFailed;
        m_logger.LogWarning("refresh failed: {}", error.what());
    }
    co_await uiThread;
    Complete(failure, failure ? std::nullopt : std::optional(connected));
}

} // namespace tailgate::uwp
