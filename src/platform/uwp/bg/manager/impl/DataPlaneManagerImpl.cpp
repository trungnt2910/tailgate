#include "DataPlaneManagerImpl.h"

#include <algorithm>
#include <optional>
#include <stdexcept>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.h>

#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Ipv4.h>

#include "common/Settings.h"
#include "common/TailgateRelay.h"

#include "service/IService.h"

namespace tailgate::uwp::bg::manager
{
namespace
{

namespace storage = winrt::Windows::Storage;

constexpr wchar_t RelayResolutionSetting[] = L"RelayResolution";
constexpr wchar_t RelayResolutionServerField[] = L"Server";
constexpr wchar_t RelayResolutionAddressField[] = L"ConnectAddress";
constexpr wchar_t RelayResolutionValidationHostField[] = L"ValidationHost";

struct RelayResolution
{
    std::string ConnectAddress;
    std::string ValidationHost;
};

std::optional<RelayResolution> LoadRelayResolution(const winrt::hstring& server)
{
    const auto value =
        Settings::Get(RelayResolutionSetting).try_as<storage::ApplicationDataCompositeValue>();
    if (!value)
    {
        return std::nullopt;
    }
    const winrt::hstring cachedServer =
        winrt::unbox_value_or<winrt::hstring>(value.TryLookup(RelayResolutionServerField), L"");
    if (cachedServer != server)
    {
        return std::nullopt;
    }
    RelayResolution result;
    result.ConnectAddress = winrt::to_string(
        winrt::unbox_value_or<winrt::hstring>(value.TryLookup(RelayResolutionAddressField), L""));
    result.ValidationHost = winrt::to_string(winrt::unbox_value_or<winrt::hstring>(
        value.TryLookup(RelayResolutionValidationHostField), L""));
    if (!tailgate::net::Ipv4Address::TryParse(result.ConnectAddress) ||
        result.ValidationHost.empty())
    {
        Settings::Remove(RelayResolutionSetting);
        return std::nullopt;
    }
    return result;
}

void StoreRelayResolution(const winrt::hstring& server, const RelayResolution& resolution)
{
    storage::ApplicationDataCompositeValue value;
    value.Insert(RelayResolutionServerField, winrt::box_value(server));
    value.Insert(RelayResolutionAddressField,
                 winrt::box_value(winrt::to_hstring(resolution.ConnectAddress)));
    value.Insert(RelayResolutionValidationHostField,
                 winrt::box_value(winrt::to_hstring(resolution.ValidationHost)));
    Settings::Set(RelayResolutionSetting, value);
}

void RemoveRelayResolution(const winrt::hstring& server)
{
    const auto value =
        Settings::Get(RelayResolutionSetting).try_as<storage::ApplicationDataCompositeValue>();
    if (value && winrt::unbox_value_or<winrt::hstring>(value.TryLookup(RelayResolutionServerField),
                                                       L"") == server)
    {
        Settings::Remove(RelayResolutionSetting);
    }
}

} // namespace

DataPlaneManagerImpl::DataPlaneManagerImpl(SessionManager& sessionManager,
                                           tailgate::hosted::PumpController& pump)
    : m_sessionManager(sessionManager), m_pump(pump)
{
}

void DataPlaneManagerImpl::Register(service::IService& service)
{
    std::lock_guard lock(m_mutex);
    if (m_started)
    {
        throw std::logic_error("Data-plane services cannot register after startup.");
    }
    if (std::find(m_services.begin(), m_services.end(), &service) == m_services.end())
    {
        m_services.push_back(&service);
    }
}

void DataPlaneManagerImpl::Start(SessionGeneration generation)
{
    std::lock_guard lock(m_mutex);
    m_pump.Reset();
    m_generation = generation;
    m_started = true;
    for (service::IService* service : m_services)
    {
        service->Start(generation);
    }
    Report(SessionEventKind::Connecting);
}

DataPlaneProbe DataPlaneManagerImpl::Probe(const std::string& server,
                                           const std::string& host,
                                           const std::string& service)
{
    m_sessionManager.Report(SessionEvent{
        .Generation = m_generation,
        .Component = SessionComponent::Probe,
        .Kind = SessionEventKind::Connecting,
    });
    TailgateRelay relay(host, service);
    if (const std::optional<RelayResolution> cached =
            LoadRelayResolution(winrt::to_hstring(server)))
    {
        relay.UseCachedEndpoint(cached->ConnectAddress, cached->ValidationHost);
    }
    else
    {
        relay.Resolve();
    }
    m_sessionManager.Report(SessionEvent{
        .Generation = m_generation,
        .Component = SessionComponent::Probe,
        .Kind = SessionEventKind::Ready,
    });
    return DataPlaneProbe{
        .ConnectAddress = relay.ConnectAddress(),
        .ValidationHost = relay.Host(),
        .Service = relay.Service(),
        .UsingCachedEndpoint = relay.IsUsingCachedEndpoint(),
    };
}

void DataPlaneManagerImpl::RememberProbe(const std::string& server, const DataPlaneProbe& probe)
{
    StoreRelayResolution(winrt::to_hstring(server),
                         RelayResolution{
                             .ConnectAddress = probe.ConnectAddress,
                             .ValidationHost = probe.ValidationHost,
                         });
}

void DataPlaneManagerImpl::InvalidateProbe(const std::string& server)
{
    RemoveRelayResolution(winrt::to_hstring(server));
}

void DataPlaneManagerImpl::Connect()
{
    std::lock_guard lock(m_mutex);
    Report(SessionEventKind::Ready);
}

void DataPlaneManagerImpl::Stop()
{
    std::lock_guard lock(m_mutex);
    m_pump.Reset();
    for (auto service = m_services.rbegin(); service != m_services.rend(); ++service)
    {
        (*service)->Stop();
    }
    m_started = false;
}

void DataPlaneManagerImpl::Reset()
{
    std::lock_guard lock(m_mutex);
    m_pump.Reset();
    for (service::IService* service : m_services)
    {
        service->Reset();
    }
    m_started = false;
    m_generation = 0;
}

void DataPlaneManagerImpl::Encapsulate(service::EncapsulationContext& context)
{
    std::lock_guard lock(m_mutex);
    if (!m_started)
    {
        return;
    }
    for (service::IService* service : m_services)
    {
        service->Encapsulate(context);
    }
    SchedulePump(context.RemoteOutput);
}

void DataPlaneManagerImpl::Decapsulate(service::DecapsulationContext& context)
{
    std::lock_guard lock(m_mutex);
    if (!m_started)
    {
        return;
    }
    for (service::IService* service : m_services)
    {
        service->Decapsulate(context);
    }
}

void DataPlaneManagerImpl::FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput,
                                      std::vector<std::uint8_t>& remoteOutput)
{
    std::lock_guard lock(m_mutex);
    if (!m_started)
    {
        return;
    }
    for (service::IService* service : m_services)
    {
        service->FlushLocal(localOutput);
    }
    // Decide after the entire incoming batch drains, not after each decoded relay frame.
    SchedulePump(remoteOutput);
}

std::size_t DataPlaneManagerImpl::ServiceCount() const
{
    std::lock_guard lock(m_mutex);
    return m_services.size();
}

void DataPlaneManagerImpl::Report(SessionEventKind kind)
{
    m_sessionManager.Report(SessionEvent{
        .Generation = m_generation,
        .Component = SessionComponent::DataPlane,
        .Kind = kind,
    });
}

void DataPlaneManagerImpl::SchedulePump(std::vector<std::uint8_t>& remoteOutput)
{
    bool pending = false;
    std::optional<tailgate::base::TimeProvider::TimePoint> deadline;
    for (const auto* service : m_services)
    {
        pending |= service->HasLocalOutput();
        const auto next = service->NextDeadline();
        if (next && (!deadline || *next < *deadline))
        {
            deadline = next;
        }
    }
    if (const auto schedule = m_pump.Update(pending, deadline))
    {
        const auto bytes = tailgate::hosted::EncodePumpSchedule(*schedule).Encode();
        remoteOutput.insert(remoteOutput.end(), bytes.begin(), bytes.end());
    }
}

} // namespace tailgate::uwp::bg::manager
