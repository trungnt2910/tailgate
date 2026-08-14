#include "SessionManagerImpl.h"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <winrt/Windows.Storage.h>
#include <winrt/base.h>

#include <nlohmann/json.hpp>

#include "common/AuthorizationState.h"
#include "common/EventSignal.h"
#include "common/HostInfo.h"
#include "common/Settings.h"

namespace tailgate::uwp::bg::manager
{

namespace
{

namespace storage = winrt::Windows::Storage;

struct StateDevice
{
    std::string Group;
    std::string Name;
    std::string Address;
    std::string Ipv6;
    std::string OperatingSystem;
    bool Online = false;
    bool ExitNodeOption = false;
};

std::string FirstIpv6(const std::vector<std::string>& addresses)
{
    const auto found = std::find_if(addresses.begin(),
                                    addresses.end(),
                                    [](const std::string& address)
                                    {
                                        return address.find(':') != std::string::npos;
                                    });
    return found == addresses.end() ? std::string() : *found;
}

std::vector<StateDevice> DevicesFromNetworkMap(const tailgate::types::netmap::NetworkConfig& config)
{
    std::vector<StateDevice> devices;
    devices.push_back(StateDevice{.Group = config.AccountDisplayName,
                                  .Name = config.SelfName,
                                  .Address = config.SelfAddress,
                                  .Ipv6 = FirstIpv6(config.SelfAddresses),
                                  .OperatingSystem = BuildHostInfo().OperatingSystem,
                                  .Online = true,
                                  .ExitNodeOption = false});
    for (const auto& peer : config.Peers)
    {
        devices.push_back(StateDevice{.Group = peer.Owner,
                                      .Name = peer.Name,
                                      .Address = peer.Address,
                                      .Ipv6 = FirstIpv6(peer.Addresses),
                                      .OperatingSystem = peer.OperatingSystem,
                                      .Online = peer.Online,
                                      .ExitNodeOption = peer.ExitNodeOption});
    }
    return devices;
}

} // namespace

class ForegroundConnectionMonitor final
{
public:
    ForegroundConnectionMonitor(const std::string& tailgateServer,
                                ForegroundCancellationHandler cancelled)
        : m_thread(
              [tailgateServer, stopHandle = m_stop.Handle(), cancelled = std::move(cancelled)]
              {
                  ConnectionCancellationMonitor monitor(winrt::to_hstring(tailgateServer));
                  const ConnectionCancellationReason reason = monitor.Wait(stopHandle);
                  if (reason == ConnectionCancellationReason::Cancelled)
                  {
                      cancelled(ForegroundCancellationReason::Cancelled);
                  }
                  else if (reason == ConnectionCancellationReason::ForegroundExited)
                  {
                      cancelled(ForegroundCancellationReason::ForegroundExited);
                  }
              })
    {
    }

    ~ForegroundConnectionMonitor()
    {
        Stop();
    }

    void Stop()
    {
        m_stop.Set();
        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    ForegroundConnectionMonitor(const ForegroundConnectionMonitor&) = delete;
    ForegroundConnectionMonitor& operator=(const ForegroundConnectionMonitor&) = delete;

private:
    EventSignal m_stop;
    std::thread m_thread;
};

SessionManagerImpl::SessionManagerImpl() = default;

SessionManagerImpl::~SessionManagerImpl()
{
    StopForegroundMonitor();
}

SessionGeneration SessionManagerImpl::BeginConnect()
{
    std::lock_guard lock(m_mutex);
    ++m_generation;
    m_components.fill(ComponentState::Idle);
    m_state = SessionState::Starting;
    return m_generation;
}

void SessionManagerImpl::Report(const SessionEvent& event)
{
    std::lock_guard lock(m_mutex);
    if (event.Generation != m_generation || m_state == SessionState::Stopping ||
        m_state == SessionState::Stopped)
    {
        return;
    }
    ComponentState& component = m_components[Index(event.Component)];
    switch (event.Kind)
    {
    case SessionEventKind::Connecting:
        component = ComponentState::Connecting;
        break;
    case SessionEventKind::AuthenticationRequired:
        component = ComponentState::AuthenticationRequired;
        break;
    case SessionEventKind::Ready:
        component = ComponentState::Ready;
        break;
    case SessionEventKind::Recovering:
        component = ComponentState::Recovering;
        break;
    case SessionEventKind::TerminalFailure:
        component = ComponentState::Failed;
        break;
    }
    UpdateAggregateState();
}

void SessionManagerImpl::Notify(SessionGeneration generation,
                                const ForegroundConnectionNotification& notification)
{
    {
        std::lock_guard lock(m_mutex);
        if (generation != m_generation || m_state == SessionState::Stopping ||
            m_state == SessionState::Stopped)
        {
            return;
        }
    }
    ConnectionMessageKind kind = ConnectionMessageKind::LoginRequired;
    switch (notification.Kind)
    {
    case ForegroundConnectionKind::LoginRequired:
        kind = ConnectionMessageKind::LoginRequired;
        break;
    case ForegroundConnectionKind::MachineApprovalRequired:
        kind = ConnectionMessageKind::MachineApprovalRequired;
        break;
    case ForegroundConnectionKind::ControlAuthorized:
        kind = ConnectionMessageKind::ControlAuthorized;
        break;
    case ForegroundConnectionKind::Failed:
        kind = ConnectionMessageKind::Failed;
        break;
    }
    (void)PublishConnectionMessage(ConnectionMessage{
        .Kind = kind,
        .Url = winrt::to_hstring(notification.Url),
        .TailgateServer = winrt::to_hstring(notification.TailgateServer),
        .ErrorCode = static_cast<UwpError::Code>(notification.ErrorCode),
    });
}

void SessionManagerImpl::StartForegroundMonitor(const std::string& tailgateServer,
                                                ForegroundCancellationHandler cancelled)
{
    StopForegroundMonitor();
    std::lock_guard lock(m_mutex);
    m_foregroundMonitor =
        std::make_unique<ForegroundConnectionMonitor>(tailgateServer, std::move(cancelled));
}

void SessionManagerImpl::StopForegroundMonitor()
{
    std::unique_ptr<ForegroundConnectionMonitor> monitor;
    {
        std::lock_guard lock(m_mutex);
        monitor = std::move(m_foregroundMonitor);
    }
    if (monitor)
    {
        monitor->Stop();
    }
}

void SessionManagerImpl::WriteState(const tailgate::types::netmap::NetworkConfig& config)
{
    nlohmann::json devicesJson = nlohmann::json::array();
    for (const StateDevice& device : DevicesFromNetworkMap(config))
    {
        devicesJson.push_back({{"Group", device.Group},
                               {"Name", device.Name},
                               {"Address", device.Address},
                               {"IPv6", device.Ipv6},
                               {"OS", device.OperatingSystem},
                               {"ExitNodeOption", device.ExitNodeOption},
                               {"Online", device.Online}});
    }
    const nlohmann::json json{
        {"TailnetName", config.Domain},
        {"TailnetDisplayName",
         config.TailnetDisplayName.empty() ? config.Domain : config.TailnetDisplayName},
        {"AccountName", config.AccountName},
        {"AccountDisplayName", config.AccountDisplayName},
        {"ProfilePicUrl", config.AccountProfilePicUrl},
        {"TailgateServer", winrt::to_string(Settings::GetString(L"TailgateServer"))},
        {"SelfAddress", config.SelfAddress},
        {"Devices", std::move(devicesJson)},
    };

    const auto folder = storage::ApplicationData::Current().LocalFolder().Path();
    const std::filesystem::path path =
        std::filesystem::path(folder.c_str()) / L"tailgate-state.json";
    {
        std::ofstream stream(path, std::ios::trunc);
        stream << json.dump();
    }
    storage::ApplicationData::Current().SignalDataChanged();
}

void SessionManagerImpl::SignalStateChanged()
{
    storage::ApplicationData::Current().SignalDataChanged();
}

void SessionManagerImpl::BeginStop()
{
    StopForegroundMonitor();
    std::lock_guard lock(m_mutex);
    ++m_generation;
    m_state = SessionState::Stopping;
}

void SessionManagerImpl::CompleteStop()
{
    std::lock_guard lock(m_mutex);
    m_components.fill(ComponentState::Idle);
    m_state = SessionState::Stopped;
}

void SessionManagerImpl::Reset()
{
    StopForegroundMonitor();
    std::lock_guard lock(m_mutex);
    ++m_generation;
    m_components.fill(ComponentState::Idle);
    m_state = SessionState::Stopped;
}

SessionGeneration SessionManagerImpl::Generation() const
{
    std::lock_guard lock(m_mutex);
    return m_generation;
}

SessionState SessionManagerImpl::State() const
{
    std::lock_guard lock(m_mutex);
    return m_state;
}

std::size_t SessionManagerImpl::Index(SessionComponent component)
{
    return static_cast<std::size_t>(component);
}

void SessionManagerImpl::UpdateAggregateState()
{
    if (std::find(m_components.begin(), m_components.end(), ComponentState::Failed) !=
        m_components.end())
    {
        m_state = SessionState::Failed;
        return;
    }
    if (std::find(m_components.begin(),
                  m_components.end(),
                  ComponentState::AuthenticationRequired) != m_components.end())
    {
        m_state = SessionState::AwaitingAuthentication;
        return;
    }
    if (std::find(m_components.begin(), m_components.end(), ComponentState::Recovering) !=
        m_components.end())
    {
        m_state = SessionState::Reconnecting;
        return;
    }
    const bool controlReady =
        m_components[Index(SessionComponent::ControlPlane)] == ComponentState::Ready;
    const bool dataReady =
        m_components[Index(SessionComponent::DataPlane)] == ComponentState::Ready;
    const bool platformReady =
        m_components[Index(SessionComponent::Platform)] == ComponentState::Ready;
    m_state =
        controlReady && dataReady && platformReady ? SessionState::Running : SessionState::Starting;
}

} // namespace tailgate::uwp::bg::manager
