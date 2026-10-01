#include "app/controller/impl/VpnProfileControllerImpl.h"

#include <chrono>
#include <cstdint>
#include <exception>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <windows.h>

#include <winrt/Windows.Foundation.Metadata.h>
#include <winrt/Windows.Networking.Connectivity.h>
#include <winrt/Windows.UI.Core.h>

#include "common/EventLoop.h"
#include "common/Settings.h"
#include "common/TimeProvider.h"
#include "common/VpnConstants.h"
#include "common/VpnReconnectState.h"

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

VpnProfileControllerImpl::~VpnProfileControllerImpl()
{
    m_statusWatch.reset();
    m_networkChanged.revoke();
    m_resuming.revoke();
    m_dataChanged.revoke();
}

void VpnProfileControllerImpl::EnsureStatusWatchStarted()
{
    const auto window = winrt::Windows::UI::Core::CoreWindow::GetForCurrentThread();
    if (m_statusWatchStarted || !window)
    {
        return;
    }
    const auto dispatcher = window.Dispatcher();
    m_statusWatch = std::make_shared<StatusWatch>(StatusWatch{.Controller = *this});
    const auto refresh = [dispatcher, weak = std::weak_ptr(m_statusWatch)]
    {
        dispatcher.RunAsync(winrt::Windows::UI::Core::CoreDispatcherPriority::Normal,
                            [weak]
                            {
                                if (const auto watch = weak.lock())
                                {
                                    watch->Controller.Refresh();
                                }
                            });
    };
    m_networkChanged =
        winrt::Windows::Networking::Connectivity::NetworkInformation::NetworkStatusChanged(
            winrt::auto_revoke,
            [refresh](const auto&)
            {
                refresh();
            });
    m_resuming = winrt::Windows::ApplicationModel::Core::CoreApplication::Resuming(
        winrt::auto_revoke,
        [refresh](const auto&, const auto&)
        {
            refresh();
        });
    m_dataChanged =
        storage::ApplicationData::Current().DataChanged(winrt::auto_revoke,
                                                        [refresh](const auto&, const auto&)
                                                        {
                                                            refresh();
                                                        });
    m_statusWatchStarted = true;
}

const VpnProfileState& VpnProfileControllerImpl::GetState() const noexcept
{
    return m_state;
}

bool VpnProfileControllerImpl::Begin(VpnProfileActivity activity, std::string_view operation)
{
    if (m_state.Busy() && m_state.Activity() != VpnProfileActivity::Refreshing)
    {
        m_logger.LogDebug("ignoring {}: VPN profile operation is active", operation);
        return false;
    }
    ++m_operationGeneration;
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
    if (std::exchange(m_refreshPending, false))
    {
        Refresh();
    }
}

void VpnProfileControllerImpl::Connect(winrt::hstring tailgateServer,
                                       winrt::hstring authKey,
                                       bool restartConnectedProfile)
{
    if (Begin(VpnProfileActivity::Connecting, "connect"))
    {
        m_connectCancelled = false;
        (void)ConnectInBackground(
            std::move(tailgateServer), std::move(authKey), restartConnectedProfile);
    }
}

void VpnProfileControllerImpl::CancelConnect()
{
    if (m_state.Busy() && m_state.Activity() == VpnProfileActivity::Connecting)
    {
        m_connectCancelled = true;
        if (m_connectOperation)
        {
            m_connectOperation.Cancel();
        }
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
    EnsureStatusWatchStarted();
    if (m_state.Busy())
    {
        m_refreshPending = true;
        return;
    }
    if (Begin(VpnProfileActivity::Refreshing, "refresh"))
    {
        m_refreshOperation = RefreshInBackground();
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

foundation::IAsyncOperation<vpn::VpnManagementErrorStatus>
VpnProfileControllerImpl::DisconnectAndWaitAsync(vpn::VpnPlugInProfile profile)
{
    const auto cancellation = co_await winrt::get_cancellation_token();
    cancellation.enable_propagation();
    const auto changed = std::make_shared<EventLoop>();
    cancellation.callback(
        [changed]
        {
            changed->Wake();
        });
    const auto registration =
        winrt::Windows::Networking::Connectivity::NetworkInformation::NetworkStatusChanged(
            winrt::auto_revoke,
            [changed](const auto&)
            {
                changed->Wake();
            });
    const auto status = co_await m_agent.DisconnectProfileAsync(profile);
    if (status != vpn::VpnManagementErrorStatus::Ok &&
        status != vpn::VpnManagementErrorStatus::AlreadyDisconnecting &&
        status != vpn::VpnManagementErrorStatus::NoConnection)
    {
        co_return status;
    }
    // DisconnectProfileAsync acknowledges the request before RAS retires the connection.
    // Wait for network changes. RS2 can report E_HANDLE after the RAS connection
    // is retired; it does not guarantee a profile reporting Disconnected.
    TimeProvider time;
    constexpr auto DisconnectTimeout = std::chrono::seconds(10);
    const auto deadline = time.After(DisconnectTimeout);
    for (;;)
    {
        if (cancellation())
        {
            throw winrt::hresult_canceled();
        }
        const vpn::VpnManagementAgent current;
        const auto profiles = co_await current.GetProfilesAsync();
        bool disconnected = true;
        for (const auto& candidate : profiles)
        {
            const auto plugin = candidate.try_as<vpn::VpnPlugInProfile>();
            if (plugin && plugin.ProfileName() == profile.ProfileName())
            {
                const auto connection = ConnectionStatusOrUnavailable(plugin, "disconnect-wait");
                disconnected = VpnReconnectState::DisconnectComplete(connection);
                if (!connection)
                {
                    m_logger.LogDebug("disconnect completed: RAS connection handle retired");
                }
                break;
            }
        }
        if (disconnected)
        {
            co_return vpn::VpnManagementErrorStatus::Ok;
        }
        co_await winrt::resume_background();
        if (changed->Wait(*deadline, 1).Status == base::EventWaitStatus::DeadlineReached)
        {
            winrt::throw_hresult(HRESULT_FROM_WIN32(ERROR_TIMEOUT));
        }
    }
}

foundation::IAsyncOperation<vpn::VpnManagementErrorStatus>
VpnProfileControllerImpl::DialProfileAsync(vpn::VpnPlugInProfile profile,
                                           std::size_t& activationRetries)
{
    const auto cancellation = co_await winrt::get_cancellation_token();
    cancellation.enable_propagation();
    // UniversalApiContract 5 is RS3. Detection itself is available on RS2.
    constexpr std::uint16_t Rs3ContractVersion = 5;
    const bool legacyWindows =
        !winrt::Windows::Foundation::Metadata::ApiInformation::IsApiContractPresent(
            L"Windows.Foundation.UniversalApiContract", Rs3ContractVersion);
    TimeProvider time;
    for (;;)
    {
        if (cancellation())
        {
            throw winrt::hresult_canceled();
        }
        const auto started = time.Now();
        const auto result = co_await m_agent.ConnectProfileAsync(profile);
        if (cancellation())
        {
            throw winrt::hresult_canceled();
        }
        if (!legacyWindows || result != vpn::VpnManagementErrorStatus::Other)
        {
            co_return result;
        }
        const auto elapsed = time.Now() - started;
        const auto connection = ConnectionStatusOrUnavailable(profile, "activation-retry");
        if (!VpnReconnectState::RetryActivation(
                legacyWindows, result, connection, elapsed, activationRetries))
        {
            co_return result;
        }
        ++activationRetries;
        m_logger.LogWarning("RS2 dial returned Other after {}ms; retrying same profile attempt={}",
                            std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(),
                            activationRetries + 1);
        // The failed asynchronous dial already waited for activation. Keep its profile and
        // foreground authorization listener alive; disconnect/delete here can tear down the
        // provider that Windows has only just launched. No sleep or status polling is needed.
    }
}

foundation::IAsyncOperation<vpn::VpnManagementErrorStatus>
VpnProfileControllerImpl::ConnectProfileAsync(vpn::VpnPlugInProfile& profile,
                                              bool afterDisconnect,
                                              winrt::hstring tailgateServer,
                                              winrt::hstring authKey)
{
    const auto cancellation = co_await winrt::get_cancellation_token();
    cancellation.enable_propagation();
    const auto changed = std::make_shared<EventLoop>();
    cancellation.callback(
        [changed]
        {
            changed->Wake();
        });
    const auto registration =
        winrt::Windows::Networking::Connectivity::NetworkInformation::NetworkStatusChanged(
            winrt::auto_revoke,
            [changed](const auto&)
            {
                changed->Wake();
            });
    TimeProvider time;
    constexpr auto RedialTimeout = std::chrono::seconds(10);
    const auto expires = time.Now() + RedialTimeout;
    const auto deadline = time.At(expires);
    bool refreshed = false;
    std::size_t activationRetries = 0;
    for (;;)
    {
        if (cancellation())
        {
            throw winrt::hresult_canceled();
        }
        if (refreshed && time.Now() >= expires)
        {
            winrt::throw_hresult(HRESULT_FROM_WIN32(ERROR_TIMEOUT));
        }
        const auto status = co_await DialProfileAsync(profile, activationRetries);
        const auto connection =
            afterDisconnect ? ConnectionStatusOrUnavailable(profile, "redial-check") : std::nullopt;
        if (VpnReconnectState::NeedsProfileReplacement(afterDisconnect, status, connection))
        {
            m_logger.LogDebug(
                "redial failed with an invalid profile handle; ensuring profile before one retry");
            // Follow the existing manual-connect recovery. EnsureProfileAsync rechecks the
            // installed profile before replacing it, and caches a newly added profile for
            // authorization retries. Do not recreate that new profile again on failure.
            bool newlyAdded = false;
            profile = co_await EnsureProfileAsync(tailgateServer, authKey, newlyAdded);
            co_return co_await DialProfileAsync(profile, activationRetries);
        }
        if (!afterDisconnect || !VpnReconnectState::RetryWithFreshAgent(status, connection))
        {
            co_return status;
        }
        if (refreshed)
        {
            // E_HANDLE retires the handle before RAS necessarily removes its connection.
            // Wait for an actual network notification, not a fixed sleep or polling loop.
            m_logger.LogDebug("redial still sees a retired connection; waiting for network change");
            co_await winrt::resume_background();
            if (changed->Wait(*deadline, 1).Status == base::EventWaitStatus::DeadlineReached)
            {
                winrt::throw_hresult(HRESULT_FROM_WIN32(ERROR_TIMEOUT));
            }
            if (cancellation())
            {
                throw winrt::hresult_canceled();
            }
        }
        // Preserve the working RS2 sequence first. Refresh only when the original
        // agent returns AlreadyConnected for a connection that has already retired.
        m_logger.LogDebug("redial returned a stale connection; refreshing management session");
        m_agent = vpn::VpnManagementAgent();
        profile = co_await FindProfileAsync();
        if (!profile)
        {
            co_return vpn::VpnManagementErrorStatus::CannotFindProfile;
        }
        refreshed = true;
    }
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
    // The node profile belongs to the control service; the optional relay is a transport.
    profile.ServerUris().Append(foundation::Uri(VpnConstants::Product::ControlUrl));
    const auto profileId = Settings::GetString(L"ProfileId");
    if (profileId.empty())
    {
        winrt::throw_hresult(E_INVALIDARG);
    }
    const std::wstring configuration =
        std::format(L"<tailgate><profileId>{}</profileId></tailgate>", profileId.c_str());
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
        // A superseded refresh still owns its outstanding Windows query. Complete it
        // before reading, deleting or dialing the profile through this management agent.
        if (m_refreshOperation)
        {
            co_await m_refreshOperation;
        }
        if (m_connectCancelled)
        {
            throw winrt::hresult_canceled();
        }
        bool newlyAdded = false;
        bool redialAfterDisconnect = false;
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
                m_connectOperation = DisconnectAndWaitAsync(profile);
                const auto disconnectStatus = co_await m_connectOperation;
                if (disconnectStatus != vpn::VpnManagementErrorStatus::Ok &&
                    disconnectStatus != vpn::VpnManagementErrorStatus::AlreadyDisconnecting &&
                    disconnectStatus != vpn::VpnManagementErrorStatus::NoConnection)
                {
                    UwpError::Throw(UwpError::Code::VpnProfileOperationFailed);
                }
                // Keep the same agent and profile for redial, as on RS2. Looking up a fresh
                // profile here can yield E_HANDLE even though DisconnectProfileAsync succeeded.
                redialAfterDisconnect = true;
                m_logger.LogDebug("redialing with the existing VPN management session");
            }
        }
        if (!connected)
        {
            if (m_connectCancelled)
            {
                throw winrt::hresult_canceled();
            }
            m_logger.LogInfo("connecting VPN profile");
            m_connectOperation =
                ConnectProfileAsync(profile, redialAfterDisconnect, tailgateServer, authKey);
            const auto status = co_await m_connectOperation;
            const bool accepted = status == vpn::VpnManagementErrorStatus::Ok ||
                                  status == vpn::VpnManagementErrorStatus::AlreadyConnected;
            if (!accepted)
            {
                m_logger.LogError("connect profile status={}", StatusValue(status));
                UwpError::Throw(UwpError::Code::VpnProfileDidNotConnect);
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
                const auto status = co_await DisconnectAndWaitAsync(profile);
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
        if (m_refreshOperation)
        {
            co_await m_refreshOperation;
        }
        auto profile = co_await FindProfileAsync();
        if (profile)
        {
            const auto status = co_await DisconnectAndWaitAsync(profile);
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
        if (m_refreshOperation)
        {
            co_await m_refreshOperation;
        }
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
        if (m_refreshOperation)
        {
            co_await m_refreshOperation;
        }
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

foundation::IAsyncAction VpnProfileControllerImpl::RefreshInBackground()
{
    const auto generation = m_operationGeneration;
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
    // A user action can supersede this read-only query while it awaits Windows.
    // Never let the older snapshot complete or overwrite that newer operation.
    if (generation == m_operationGeneration)
    {
        Complete(failure, failure ? std::nullopt : std::optional(connected));
    }
}

} // namespace tailgate::uwp
