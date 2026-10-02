#include "ProfileRecoveryManagerImpl.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>

#include <windows.h>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Foundation.Metadata.h>
#include <winrt/Windows.Networking.Connectivity.h>
#include <winrt/Windows.Networking.Vpn.h>

#include <tailgate/base/Logger.h>

#include "common/EventLoop.h"
#include "common/Settings.h"
#include "common/TimeProvider.h"
#include "common/UwpFormat.h"
#include "common/VpnConstants.h"
#include "common/VpnReconnectState.h"
#include "common/WinrtOperation.h"

#include "manager/ProfileRecoveryState.h"

namespace tailgate::uwp::bg::manager
{
namespace
{
namespace vpn = winrt::Windows::Networking::Vpn;
using namespace std::chrono_literals;
constexpr auto RecoveryTimeout = 90s;
constexpr auto ManagementTimeout = 20s;
constexpr auto DialTimeout = 45s;
constexpr auto DisconnectTimeout = 10s;
constexpr auto RecoveryUsedKey = L"BackgroundProfileRecoveryUsed";

} // namespace

struct ProfileRecoveryCoordinator
{
    std::mutex Mutex;
    ProfileRecoveryState State;
    std::stop_source Stop;
    winrt::hstring ProfileId;
    bool ConnectionSucceeded = false;
    base::Logger Logger{"profile-recovery"};
};

namespace
{

std::optional<vpn::VpnManagementConnectionStatus> Status(const vpn::VpnPlugInProfile& profile)
{
    try
    {
        return profile.ConnectionStatus();
    }
    catch (const winrt::hresult_error& error)
    {
        if (error.code() == E_HANDLE)
        {
            return std::nullopt;
        }
        throw;
    }
}

class Recovery final
{
public:
    Recovery(ProfileRecoveryCoordinator& coordinator,
             std::stop_token stop,
             winrt::hstring profileId)
        : m_coordinator(coordinator),
          m_stop(stop),
          m_profileId(std::move(profileId)),
          m_expires(m_time.Now() + RecoveryTimeout)
    {
    }

    void Run()
    {
        const auto changed = std::make_shared<EventLoop>();
        const std::stop_callback stopped(m_stop,
                                         [changed]
                                         {
                                             changed->Wake();
                                         });
        const auto notification =
            winrt::Windows::Networking::Connectivity::NetworkInformation::NetworkStatusChanged(
                winrt::auto_revoke,
                [changed](const auto&)
                {
                    changed->Wake();
                });
        vpn::VpnManagementAgent agent;
        auto profile = FindProfile(agent);
        if (!profile)
        {
            throw winrt::hresult_invalid_argument();
        }

        auto& logger = m_coordinator.Logger;
        logger.LogInfo("disconnect begin");
        const auto result = AwaitOperation(
            agent.DisconnectProfileAsync(profile), Remaining(ManagementTimeout), m_stop);
        logger.LogInfo("disconnect returned status={}", static_cast<int>(result));
        if (result != vpn::VpnManagementErrorStatus::Ok &&
            result != vpn::VpnManagementErrorStatus::AlreadyDisconnecting &&
            result != vpn::VpnManagementErrorStatus::NoConnection)
        {
            throw winrt::hresult_error(E_FAIL);
        }

        const auto disconnectExpires = m_time.Now() + DisconnectTimeout;
        const auto deadline = m_time.At(disconnectExpires);
        for (;;)
        {
            Check();
            if (m_time.Now() >= disconnectExpires)
            {
                throw winrt::hresult_error(HRESULT_FROM_WIN32(ERROR_TIMEOUT));
            }
            const vpn::VpnManagementAgent observer;
            const auto current = FindProfile(observer);
            if (!current)
            {
                throw winrt::hresult_canceled(); // The profile was removed by the user.
            }
            if (VpnReconnectState::DisconnectComplete(Status(current)))
            {
                break;
            }
            logger.LogInfo("waiting for RAS disconnect notification");
            if (changed->Wait(*deadline, 1).Status == base::EventWaitStatus::DeadlineReached)
            {
                throw winrt::hresult_error(HRESULT_FROM_WIN32(ERROR_TIMEOUT));
            }
        }
        logger.LogInfo("disconnect confirmed; redialing original profile");
        {
            auto& coordinator = m_coordinator;
            std::lock_guard lock(coordinator.Mutex);
            if (!coordinator.State.BeginDial())
            {
                throw winrt::hresult_canceled();
            }
        }
        constexpr std::uint16_t Rs3ContractVersion = 5;
        const bool legacy =
            !winrt::Windows::Foundation::Metadata::ApiInformation::IsApiContractPresent(
                L"Windows.Foundation.UniversalApiContract", Rs3ContractVersion);
        std::size_t activationRetries = 0;
        bool refreshed = false;
        for (;;)
        {
            Check();
            const auto started = m_time.Now();
            logger.LogInfo("redial begin activation-retries={} refreshed-agent={}",
                           activationRetries,
                           refreshed);
            const auto dial =
                AwaitOperation(agent.ConnectProfileAsync(profile), Remaining(DialTimeout), m_stop);
            Check();
            const auto status = Status(profile);
            logger.LogInfo(
                "redial returned status={} connection-status={} elapsed-ms={}",
                static_cast<int>(dial),
                status ? static_cast<int>(*status) : -1,
                std::chrono::duration_cast<std::chrono::milliseconds>(m_time.Now() - started)
                    .count());
            const bool accepted = dial == vpn::VpnManagementErrorStatus::Ok ||
                                  dial == vpn::VpnManagementErrorStatus::AlreadyConnected;
            bool callbackConnected = false;
            {
                auto& coordinator = m_coordinator;
                std::lock_guard lock(coordinator.Mutex);
                callbackConnected = coordinator.ConnectionSucceeded;
            }
            bool connected =
                status == vpn::VpnManagementConnectionStatus::Connected || callbackConnected;
            if (accepted && !connected)
            {
                // Activation can use a new background process; its successful callback
                // cannot update this process's coordinator, and the cached RAS handle may be stale.
                const vpn::VpnManagementAgent observer;
                const auto observed = FindProfile(observer);
                connected =
                    observed && Status(observed) == vpn::VpnManagementConnectionStatus::Connected;
            }
            if (accepted && connected)
            {
                logger.LogInfo("recovery completed: profile connected");
                return;
            }
            if (VpnReconnectState::RetryActivation(
                    legacy, dial, status, m_time.Now() - started, activationRetries))
            {
                ++activationRetries;
                continue;
            }
            if (!refreshed && VpnReconnectState::RetryWithFreshAgent(dial, status))
            {
                agent = vpn::VpnManagementAgent();
                profile = FindProfile(agent);
                if (!profile)
                {
                    throw winrt::hresult_canceled();
                }
                refreshed = true;
                continue;
            }
            // Do not delete/recreate profiles or loop forever on permanent activation errors.
            throw winrt::hresult_error(E_FAIL);
        }
    }

private:
    void Check() const
    {
        if (m_stop.stop_requested() || Settings::GetString(L"ProfileId") != m_profileId)
        {
            throw winrt::hresult_canceled();
        }
        if (m_time.Now() >= m_expires)
        {
            throw winrt::hresult_error(HRESULT_FROM_WIN32(ERROR_TIMEOUT));
        }
    }

    std::chrono::seconds Remaining(std::chrono::seconds maximum) const
    {
        Check();
        return std::min(maximum, std::chrono::ceil<std::chrono::seconds>(m_expires - m_time.Now()));
    }

    vpn::VpnPlugInProfile FindProfile(const vpn::VpnManagementAgent& agent) const
    {
        for (const auto& candidate :
             AwaitOperation(agent.GetProfilesAsync(), Remaining(ManagementTimeout), m_stop))
        {
            const auto profile = candidate.try_as<vpn::VpnPlugInProfile>();
            if (profile && profile.ProfileName() == VpnConstants::Product::Name)
            {
                return profile;
            }
        }
        return nullptr;
    }

    ProfileRecoveryCoordinator& m_coordinator;
    std::stop_token m_stop;
    winrt::hstring m_profileId;
    TimeProvider m_time;
    base::TimeProvider::TimePoint m_expires;
};

} // namespace

ProfileRecoveryManagerImpl::ProfileRecoveryManagerImpl()
    : m_coordinator(std::make_unique<ProfileRecoveryCoordinator>())
{
}

ProfileRecoveryManagerImpl::~ProfileRecoveryManagerImpl() = default;

void ProfileRecoveryManagerImpl::EnterConnect()
{
    auto& current = *m_coordinator;
    std::lock_guard lock(current.Mutex);
    current.State.EnterConnect();
}

void ProfileRecoveryManagerImpl::LeaveConnect()
{
    auto& current = *m_coordinator;
    std::lock_guard lock(current.Mutex);
    current.State.LeaveConnect();
}

bool ProfileRecoveryManagerImpl::Request()
{
    auto& current = *m_coordinator;
    std::lock_guard lock(current.Mutex);
    if (Settings::GetString(RecoveryUsedKey) == L"true" || !current.State.Request())
    {
        current.Logger.LogWarning(
            "recovery declined: already active or budget used since last successful connection");
        return false;
    }
    // Persist the budget so a newly activated background host cannot start an endless redial cycle.
    try
    {
        Settings::SetString(RecoveryUsedKey, L"true");
        current.Stop = std::stop_source{};
        current.ProfileId = Settings::GetString(L"ProfileId");
    }
    catch (...)
    {
        current.State.Finish();
        throw;
    }
    current.Logger.LogInfo(
        "recovery queued; waiting for failed-attempt termination and callback return");
    return true;
}

void ProfileRecoveryManagerImpl::AttemptTerminated()
{
    auto& current = *m_coordinator;
    std::lock_guard lock(current.Mutex);
    current.State.AttemptTerminated();
}

void ProfileRecoveryManagerImpl::RunPending(std::stop_token cancellation)
{
    auto& current = *m_coordinator;
    std::stop_source stop(std::nostopstate);
    winrt::hstring profileId;
    {
        std::lock_guard lock(current.Mutex);
        if (!current.State.Claim())
        {
            return;
        }
        stop = current.Stop;
        profileId = current.ProfileId;
        current.ConnectionSucceeded = false;
    }
    const std::stop_callback cancelled(cancellation,
                                       [stop]() mutable
                                       {
                                           stop.request_stop();
                                       });
    current.Logger.LogInfo("recovering VPN profile after failed channel setup");
    try
    {
        Recovery(current, stop.get_token(), profileId).Run();
    }
    catch (...)
    {
        current.Logger.LogError("recovery failed cancelled={} hresult=0x{:08x}: {}",
                                stop.stop_requested(),
                                static_cast<std::uint32_t>(winrt::to_hresult().value),
                                winrt::to_message());
    }
    {
        std::lock_guard lock(current.Mutex);
        current.State.Finish();
        current.ProfileId.clear();
    }
    current.Logger.LogInfo("recovery finished; releasing task deferral");
}

void ProfileRecoveryManagerImpl::Disconnecting()
{
    auto& current = *m_coordinator;
    std::stop_source stop(std::nostopstate);
    {
        std::lock_guard lock(current.Mutex);
        if (current.State.Disconnecting())
        {
            stop = current.Stop;
        }
    }
    stop.request_stop();
}

void ProfileRecoveryManagerImpl::Connected()
{
    auto& current = *m_coordinator;
    std::lock_guard lock(current.Mutex);
    current.ConnectionSucceeded = true;
    Settings::Remove(RecoveryUsedKey);
}

} // namespace tailgate::uwp::bg::manager
