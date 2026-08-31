#include "ControlPlaneManagerImpl.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.h>
#include <winrt/base.h>

#include <tailgate/control/client/RetryBackoff.h>

#include "common/Settings.h"
#include "common/TcpSocketFactory.h"
#include "common/UwpFormat.h"

#include "manager/ControlRegistrationNotification.h"

namespace tailgate::uwp::bg::manager
{
namespace storage = winrt::Windows::Storage;
using namespace std::chrono_literals;

namespace
{

constexpr std::chrono::seconds ControlIoTimeout(90);
constexpr std::chrono::seconds PlaintextControlConnectTimeout(5);
constexpr std::chrono::seconds ReconnectMinimumBackoff(5);
constexpr std::chrono::seconds ReconnectMaximumBackoff(60);

winrt::hstring GeneratePrivateKeyText()
{
    const tailgate::crypto::Bytes32 key = tailgate::crypto::GeneratePrivateKey();
    return winrt::to_hstring(tailgate::crypto::BytesToHex(key.data(), key.size()));
}

std::optional<tailgate::crypto::Bytes32> DecodePrivateKey(const winrt::hstring& encoded)
{
    if (encoded.empty())
    {
        return std::nullopt;
    }
    try
    {
        const std::vector<std::uint8_t> bytes =
            tailgate::crypto::HexToBytes(winrt::to_string(encoded));
        if (bytes.size() == tailgate::crypto::Bytes32{}.size())
        {
            tailgate::crypto::Bytes32 result{};
            std::copy(bytes.begin(), bytes.end(), result.begin());
            return result;
        }
    }
    catch (const std::runtime_error&)
    {
    }
    return std::nullopt;
}

std::optional<tailgate::crypto::Bytes32> LoadPrivateKey(const winrt::hstring& name)
{
    return DecodePrivateKey(Settings::GetString(name));
}

tailgate::crypto::Bytes32 LoadOrCreatePrivateKey(const winrt::hstring& name)
{
    const Settings::Value stored =
        Settings::GetOrCreate(name,
                              []
                              {
                                  return winrt::box_value(GeneratePrivateKeyText());
                              });
    if (const std::optional<tailgate::crypto::Bytes32> existing =
            DecodePrivateKey(winrt::unbox_value_or<winrt::hstring>(stored, L"")))
    {
        return *existing;
    }

    const winrt::hstring replacement = GeneratePrivateKeyText();
    Settings::SetString(name, replacement);
    return *DecodePrivateKey(replacement);
}

class IdentityStorageError final : public std::runtime_error
{
public:
    IdentityStorageError()
        : std::runtime_error("The registered UWP node identity is missing or invalid.")
    {
    }
};

} // namespace

class ControlPlaneManagerImpl::RegistrationHandler final
    : public tailgate::control::client::RegistrationHandler
{
public:
    explicit RegistrationHandler(ControlPlaneManagerImpl& owner) noexcept : m_owner(owner)
    {
    }

    void StateChanged(const tailgate::control::client::RegistrationResult& state) override
    {
        const std::optional<ForegroundConnectionNotification> notification =
            BuildAuthenticationNotification(
                state, winrt::to_string(Settings::GetString(L"TailgateServer")));
        if (!notification)
        {
            return;
        }
        const bool loginRequired = notification->Kind == ForegroundConnectionKind::LoginRequired;
        if (loginRequired)
        {
            Settings::SetString(L"NodeFollowupUrl", winrt::to_hstring(state.AuthorizationUrl));
            m_owner.m_logger.LogInfo(
                "waiting for interactive login code={}",
                state.AuthorizationCode.empty() ? "unavailable" : state.AuthorizationCode.c_str());
        }
        else
        {
            m_owner.m_logger.LogInfo("waiting for machine approval url={}", state.ApprovalUrl);
        }
        m_owner.Report(SessionEventKind::AuthenticationRequired);
        m_owner.m_sessionManager.Notify(m_owner.m_generation, *notification);
    }

    bool WaitForRetry(std::chrono::milliseconds delay) override
    {
        return m_owner.WaitForRetry(delay);
    }

private:
    ControlPlaneManagerImpl& m_owner;
};

ControlPlaneManagerImpl::ControlPlaneManagerImpl(
    SessionManager& sessionManager,
    tailgate::control::client::SessionFactory& controlSessionFactory,
    TcpSocketFactory& socketFactory)
    : m_sessionManager(sessionManager),
      m_controlSessionFactory(controlSessionFactory),
      m_socketFactory(socketFactory)
{
}

ControlPlaneManagerImpl::~ControlPlaneManagerImpl()
{
    StopMaintenance();
}

void ControlPlaneManagerImpl::Start(SessionGeneration generation)
{
    m_generation = generation;
    m_stopping = false;
    Report(SessionEventKind::Connecting);
}

void ControlPlaneManagerImpl::LoadIdentity(bool registered)
{
    if (!registered)
    {
        m_machinePrivateKey = LoadOrCreatePrivateKey(L"MachinePrivateKey");
        m_nodePrivateKey = LoadOrCreatePrivateKey(L"NodePrivateKey");
        m_discoPrivateKey = LoadOrCreatePrivateKey(L"DiscoPrivateKey");
        return;
    }
    const std::optional<tailgate::crypto::Bytes32> machine = LoadPrivateKey(L"MachinePrivateKey");
    const std::optional<tailgate::crypto::Bytes32> node = LoadPrivateKey(L"NodePrivateKey");
    const std::optional<tailgate::crypto::Bytes32> disco = LoadPrivateKey(L"DiscoPrivateKey");
    if (!machine || !node || !disco)
    {
        throw IdentityStorageError();
    }
    m_machinePrivateKey = *machine;
    m_nodePrivateKey = *node;
    m_discoPrivateKey = *disco;
}

tailgate::control::client::RegistrationResult
ControlPlaneManagerImpl::Connect(const std::string& authKey)
{
    m_logger.LogInfo("starting control registration");
    std::unique_ptr<tailgate::control::client::Session> controlSession =
        m_controlSessionFactory.CreateSession(
            tailgate::control::client::SessionOptions{
                .Host = {},
                .MachinePrivateKey = m_machinePrivateKey,
                .NodePrivateKey = m_nodePrivateKey,
                .ExternalNodePublicKey = std::nullopt,
                .NetworkInterface = {},
                .ReadinessToken = {},
                .IoTimeout = ControlIoTimeout,
                .PlaintextConnectTimeout = PlaintextControlConnectTimeout,
            },
            m_socketFactory);
    controlSession->SetDiscoPrivateKey(m_discoPrivateKey);
    {
        std::lock_guard lock(m_mutex);
        if (m_stopping)
        {
            throw std::runtime_error("Control maintenance is stopping.");
        }
        m_controlSession = std::move(controlSession);
    }
    m_controlSession->SetReadTimeout(std::nullopt);
    RegistrationHandler registrationHandler(*this);
    const tailgate::control::client::RegistrationOptions options{
        .InitialFollowupUrl = winrt::to_string(Settings::GetString(L"NodeFollowupUrl")),
        .ReauthorizationKey = {},
        .Handler = &registrationHandler,
    };
    tailgate::control::client::RegistrationResult registration;
    try
    {
        registration = m_controlSession->RegisterUntilAuthorized(authKey, options);
    }
    catch (...)
    {
        m_controlSession->SetReadTimeout(ControlIoTimeout);
        throw;
    }
    m_controlSession->SetReadTimeout(std::nullopt);
    if (!registration.Network)
    {
        throw std::runtime_error("Control registration completed without a network map.");
    }
    const tailgate::types::netmap::NetworkConfig& config = *registration.Network;
    const std::string key =
        "nodekey:" + tailgate::crypto::BytesToHex(m_controlSession->NodePublicKey().data(),
                                                  m_controlSession->NodePublicKey().size());
    if (config.SelfKey() != key)
    {
        throw ControlIdentityChangedError();
    }
    m_nodePublicKey = m_controlSession->NodePublicKey();
    Settings::SetString(L"RegistrationComplete", L"true");
    Settings::Remove(L"AuthKey");
    Settings::Remove(L"NodeFollowupUrl");
    storage::ApplicationData::Current().SignalDataChanged();
    m_controlSession->UpdateHostInfo(config.DerpRegion());
    if (!registration.NetworkMapStreaming)
    {
        m_controlSession->SetPreferredDerp(config.DerpRegion());
    }
    Report(SessionEventKind::Ready);
    m_logger.LogInfo("control registration completed address={}", config.SelfAddress());
    return registration;
}

void ControlPlaneManagerImpl::StartMaintenance(NetworkMapHandler networkMapHandler)
{
    if (m_maintenanceThread.joinable())
    {
        throw std::logic_error("Control maintenance is already running.");
    }
    m_stopping = false;
    m_maintenanceThread = std::thread(
        [this, networkMapHandler = std::move(networkMapHandler)]
        {
            winrt::init_apartment(winrt::apartment_type::multi_threaded);
            tailgate::control::client::RetryBackoff reconnectBackoff(ReconnectMinimumBackoff,
                                                                     ReconnectMaximumBackoff);
            bool connected = true;
            while (!m_stopping)
            {
                try
                {
                    if (!connected)
                    {
                        tailgate::control::client::RegistrationResult registration = Connect("");
                        if (!registration.Network)
                        {
                            throw std::runtime_error(
                                "Control maintenance requires interactive login.");
                        }
                        networkMapHandler(std::move(*registration.Network));
                        connected = true;
                        reconnectBackoff.Reset();
                        m_logger.LogInfo("control stream reconnected");
                    }
                    tailgate::types::netmap::NetworkConfig update =
                        m_controlSession->WaitForNetworkMap();
                    networkMapHandler(std::move(update));
                }
                catch (const ControlIdentityChangedError& error)
                {
                    m_logger.LogError("control maintenance stopped: {}", error.what());
                    break;
                }
                catch (const winrt::hresult_error& error)
                {
                    if (m_stopping)
                    {
                        break;
                    }
                    m_logger.LogWarning("control stream failed hresult={} message={}",
                                        error.code(),
                                        error.message());
                }
                catch (const std::exception& error)
                {
                    if (m_stopping)
                    {
                        break;
                    }
                    m_logger.LogWarning("control stream failed: {}", error.what());
                }
                connected = false;
                const std::chrono::milliseconds retryDelay = reconnectBackoff.NextDelay();
                m_logger.LogInfo("reconnecting control stream in {}ms", retryDelay.count());
                if (!WaitForRetry(retryDelay))
                {
                    break;
                }
            }
            winrt::uninit_apartment();
        });
}

void ControlPlaneManagerImpl::StopMaintenance()
{
    RequestStop();
    if (m_maintenanceThread.joinable())
    {
        m_maintenanceThread.join();
    }
}

void ControlPlaneManagerImpl::RequestStop()
{
    m_stopping = true;
    m_stopChanged.notify_all();
    std::lock_guard lock(m_mutex);
    if (m_controlSession)
    {
        try
        {
            m_controlSession->Close();
        }
        catch (const winrt::hresult_error& error)
        {
            m_logger.LogWarning("control cleanup failed hresult={}", error.code());
        }
    }
}

void ControlPlaneManagerImpl::Stop()
{
    StopMaintenance();
}

void ControlPlaneManagerImpl::Reset()
{
    StopMaintenance();
    std::lock_guard lock(m_mutex);
    m_controlSession.reset();
}

bool ControlPlaneManagerImpl::IsStopping() const
{
    return m_stopping;
}

const tailgate::crypto::Bytes32& ControlPlaneManagerImpl::NodePrivateKey() const
{
    return m_nodePrivateKey;
}

const tailgate::crypto::Bytes32& ControlPlaneManagerImpl::NodePublicKey() const
{
    return m_nodePublicKey;
}

const tailgate::crypto::Bytes32& ControlPlaneManagerImpl::DiscoPrivateKey() const
{
    return m_discoPrivateKey;
}

bool ControlPlaneManagerImpl::WaitForRetry(std::chrono::milliseconds delay) const
{
    std::unique_lock lock(m_mutex);
    return !m_stopChanged.wait_for(lock,
                                   delay,
                                   [this]()
                                   {
                                       return m_stopping.load();
                                   });
}

void ControlPlaneManagerImpl::Report(SessionEventKind kind)
{
    m_sessionManager.Report(SessionEvent{
        .Generation = m_generation,
        .Component = SessionComponent::ControlPlane,
        .Kind = kind,
    });
}

} // namespace tailgate::uwp::bg::manager
