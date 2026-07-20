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
#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Storage.h>
#include <winrt/base.h>

#include <tailgate/control/ControlDialer.h>
#include <tailgate/control/RetryBackoff.h>
#include <tailgate/protocol/ControlHandshake.h>

#include "common/UwpTcpStream.h"

#include "common/HostInfo.h"
#include "common/Settings.h"

namespace tailgate::uwp::bg::manager
{
namespace sockets = winrt::Windows::Networking::Sockets;
namespace storage = winrt::Windows::Storage;
using namespace std::chrono_literals;

namespace
{

constexpr std::chrono::seconds ControlIoTimeout(90);
constexpr std::chrono::seconds PlaintextControlConnectTimeout(5);
constexpr std::chrono::milliseconds RetryWaitSlice(100);
constexpr std::chrono::seconds ReconnectMinimumBackoff(5);
constexpr std::chrono::seconds ReconnectMaximumBackoff(60);
constexpr std::chrono::milliseconds ReconnectPollInterval(100);

winrt::hstring GeneratePrivateKeyText()
{
    const protocol::Bytes32 key = protocol::GeneratePrivateKey();
    return winrt::to_hstring(protocol::BytesToHex(key.data(), key.size()));
}

std::optional<protocol::Bytes32> DecodePrivateKey(const winrt::hstring& encoded)
{
    if (encoded.empty())
    {
        return std::nullopt;
    }
    try
    {
        const std::vector<std::uint8_t> bytes = protocol::HexToBytes(winrt::to_string(encoded));
        if (bytes.size() == protocol::Bytes32{}.size())
        {
            protocol::Bytes32 result{};
            std::copy(bytes.begin(), bytes.end(), result.begin());
            return result;
        }
    }
    catch (const std::runtime_error&)
    {
    }
    return std::nullopt;
}

std::optional<protocol::Bytes32> LoadPrivateKey(const winrt::hstring& name)
{
    return DecodePrivateKey(Settings::GetString(name));
}

protocol::Bytes32 LoadOrCreatePrivateKey(const winrt::hstring& name)
{
    const Settings::Value stored =
        Settings::GetOrCreate(name,
                              []
                              {
                                  return winrt::box_value(GeneratePrivateKeyText());
                              });
    if (const std::optional<protocol::Bytes32> existing =
            DecodePrivateKey(winrt::unbox_value_or<winrt::hstring>(stored, L"")))
    {
        return *existing;
    }

    const winrt::hstring replacement = GeneratePrivateKeyText();
    Settings::SetString(name, replacement);
    return *DecodePrivateKey(replacement);
}

struct IdentityStorageError final : std::runtime_error
{
    IdentityStorageError()
        : std::runtime_error("The registered UWP node identity is missing or invalid.")
    {
    }
};

} // namespace

ControlPlaneManagerImpl::ControlPlaneManagerImpl(SessionManager& sessionManager)
    : m_sessionManager(sessionManager)
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
    const std::optional<protocol::Bytes32> machine = LoadPrivateKey(L"MachinePrivateKey");
    const std::optional<protocol::Bytes32> node = LoadPrivateKey(L"NodePrivateKey");
    const std::optional<protocol::Bytes32> disco = LoadPrivateKey(L"DiscoPrivateKey");
    if (!machine || !node || !disco)
    {
        throw IdentityStorageError();
    }
    m_machinePrivateKey = *machine;
    m_nodePrivateKey = *node;
    m_discoPrivateKey = *disco;
}

control::RegistrationResult ControlPlaneManagerImpl::Connect(const std::string& authKey)
{
    m_logger.LogInfo("starting control registration");
    std::unique_ptr<control::ControlClient> client;
    control::ControlDialOutcome<std::unique_ptr<UwpTcpStream>> dialed = control::DialControlStream(
        []
        {
            return std::make_unique<UwpTcpStream>(protocol::ControlHandshake::DefaultHost,
                                                  protocol::ControlHandshake::PlaintextService,
                                                  sockets::SocketProtectionLevel::PlainSocket,
                                                  ControlIoTimeout,
                                                  PlaintextControlConnectTimeout);
        },
        []
        {
            return std::make_unique<UwpTcpStream>(protocol::ControlHandshake::DefaultHost,
                                                  protocol::ControlHandshake::TlsService,
                                                  sockets::SocketProtectionLevel::Tls12,
                                                  ControlIoTimeout);
        },
        [&](IByteStream& stream)
        {
            client = std::make_unique<control::ControlClient>(
                stream, m_machinePrivateKey, m_nodePrivateKey, BuildHostInfo());
        });
    m_logger.LogInfo("{}",
                     dialed.UsedTls ? "control connected through the TLS fallback"
                                    : "control connected through plaintext ts2021");
    client->SetDiscoPrivateKey(m_discoPrivateKey);
    {
        std::lock_guard lock(m_mutex);
        if (m_stopping)
        {
            throw std::runtime_error("Control maintenance is stopping.");
        }
        m_client = std::move(client);
        m_stream = std::move(dialed.Stream);
    }
    m_stream->SetReadTimeout(std::nullopt);
    control::RegistrationOptions options;
    options.InitialFollowupUrl = winrt::to_string(Settings::GetString(L"NodeFollowupUrl"));
    options.StateChanged = [&](const control::RegistrationResult& state)
    {
        const bool loginRequired = state.State == control::RegistrationState::LoginRequired;
        const std::string actionUrl = loginRequired ? state.AuthorizationUrl : state.ApprovalUrl;
        if (loginRequired)
        {
            Settings::SetString(L"NodeFollowupUrl", winrt::to_hstring(state.AuthorizationUrl));
            m_logger.LogInfo("waiting for interactive login code={}",
                             state.AuthorizationCode.empty() ? "unavailable"
                                                             : state.AuthorizationCode.c_str());
        }
        else
        {
            m_logger.LogInfo("waiting for machine approval url={}", state.ApprovalUrl);
        }
        Report(SessionEventKind::AuthenticationRequired);
        m_sessionManager.Notify(
            m_generation,
            ForegroundConnectionNotification{
                .Kind = loginRequired ? ForegroundConnectionKind::LoginRequired
                                      : ForegroundConnectionKind::MachineApprovalRequired,
                .Url = actionUrl,
                .TailgateServer = winrt::to_string(Settings::GetString(L"TailgateServer")),
            });
    };
    options.WaitForRetry = [&](std::chrono::milliseconds delay)
    {
        return WaitForRetry(delay);
    };
    control::RegistrationResult registration;
    try
    {
        registration = m_client->RegisterUntilAuthorized(authKey, options);
    }
    catch (...)
    {
        m_stream->SetReadTimeout(ControlIoTimeout);
        throw;
    }
    m_stream->SetReadTimeout(ControlIoTimeout);
    if (!registration.Network)
    {
        throw std::runtime_error("Control registration completed without a network map.");
    }
    const control::NetworkConfig& config = *registration.Network;
    const std::string key = "nodekey:" + protocol::BytesToHex(m_client->NodePublicKey().data(),
                                                              m_client->NodePublicKey().size());
    if (config.SelfKey != key)
    {
        throw ControlIdentityChangedError();
    }
    m_nodePublicKey = m_client->NodePublicKey();
    Settings::SetString(L"RegistrationComplete", L"true");
    Settings::Remove(L"AuthKey");
    Settings::Remove(L"NodeFollowupUrl");
    storage::ApplicationData::Current().SignalDataChanged();
    m_client->UpdateHostInfo(config.DerpRegion);
    if (!registration.NetworkMapStreaming)
    {
        m_client->SetPreferredDerp(config.DerpRegion);
    }
    m_stream->SetNonBlockingReads(true);
    Report(SessionEventKind::Ready);
    m_logger.LogInfo("control registration completed address={}", config.SelfAddress);
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
            control::RetryBackoff reconnectBackoff(ReconnectMinimumBackoff,
                                                   ReconnectMaximumBackoff);
            bool connected = true;
            while (!m_stopping)
            {
                try
                {
                    if (!connected)
                    {
                        control::RegistrationResult registration = Connect("");
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
                    if (std::optional<control::NetworkConfig> update = m_client->PollNetworkMap())
                    {
                        networkMapHandler(std::move(*update));
                        continue;
                    }
                    m_stream->WaitForPendingRead();
                    continue;
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
                for (auto waited = std::chrono::milliseconds(0); waited < retryDelay && !m_stopping;
                     waited += ReconnectPollInterval)
                {
                    std::this_thread::sleep_for(ReconnectPollInterval);
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
    std::lock_guard lock(m_mutex);
    if (m_stream)
    {
        try
        {
            m_stream->Close();
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
    m_client.reset();
    m_stream.reset();
}

bool ControlPlaneManagerImpl::IsStopping() const
{
    return m_stopping;
}

const protocol::Bytes32& ControlPlaneManagerImpl::NodePrivateKey() const
{
    return m_nodePrivateKey;
}

const protocol::Bytes32& ControlPlaneManagerImpl::NodePublicKey() const
{
    return m_nodePublicKey;
}

const protocol::Bytes32& ControlPlaneManagerImpl::DiscoPrivateKey() const
{
    return m_discoPrivateKey;
}

bool ControlPlaneManagerImpl::WaitForRetry(std::chrono::milliseconds delay) const
{
    std::chrono::milliseconds waited(0);
    while (waited < delay && !m_stopping)
    {
        const std::chrono::milliseconds slice = std::min(RetryWaitSlice, delay - waited);
        std::this_thread::sleep_for(slice);
        waited += slice;
    }
    return !m_stopping;
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
