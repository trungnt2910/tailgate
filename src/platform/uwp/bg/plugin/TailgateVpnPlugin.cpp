#include "TailgateVpnPlugin.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <format>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <stop_token>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Networking.Vpn.h>
#include <winrt/Windows.Networking.h>
#include <winrt/Windows.Storage.Streams.h>
#include <winrt/base.h>

#include <tailgate/base/Logger.h>
#include <tailgate/control/client/ControlClient.h>
#include <tailgate/control/client/RetryBackoff.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/derp/Client.h>
#include <tailgate/disco/Disco.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/ClientSession.h>
#include <tailgate/hosted/Connection.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/hosted/StreamTransport.h>
#include <tailgate/ipn/ipnlocal/SwitchingNode.h>
#include <tailgate/ipn/ipnlocal/UnderlaySelection.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/net/packet/Tsmp.h>
#include <tailgate/types/nettype/TcpSocket.h>
#include <tailgate/wgengine/router/Config.h>
#include <tailgate/wgengine/wireguard/Router.h>

#include "common/AuthorizationState.h"
#include "common/HostInfo.h"
#include "common/NetworkAdapter.h"
#include "common/NetworkMonitor.h"
#include "common/ResourceLoader.h"
#include "common/Settings.h"
#include "common/ThreadApartment.h"
#include "common/UwpError.h"
#include "common/UwpFireAndForget.h"
#include "common/VpnConstants.h"
#include "tstun/ChannelAdapter.h"

#include "manager/ChannelPolicy.h"

#include "service/ExitNodeService.h"

#include "DI.h"
#include "HostedConnection.h"
#include "ModeRequests.h"
#include "NativeConnection.h"
#include "NodeContext.h"

namespace tailgate::uwp
{
namespace
{

namespace foundation = winrt::Windows::Foundation;
namespace networking = winrt::Windows::Networking;
namespace streams = winrt::Windows::Storage::Streams;
namespace vpn = winrt::Windows::Networking::Vpn;
using namespace bg;
using namespace bg::manager;
using namespace bg::service;
using namespace std::chrono_literals;

constexpr std::chrono::seconds InitialConnectMinimumBackoff(1);
constexpr std::chrono::seconds InitialConnectMaximumBackoff(30);
enum class ReconnectReason
{
    NetworkPolicyUpdate,
    ExitNodeChange,
};

class TailgateVpnPlugin : public winrt::implements<TailgateVpnPlugin, vpn::IVpnPlugIn>
{
public:
    TailgateVpnPlugin()
        : m_injector(CreatePluginInjector()),
          m_events(m_injector->create<std::shared_ptr<tailgate::base::EventLoop>>()),
          m_time(m_injector->create<tailgate::base::TimeProvider&>()),
          m_channelAdapter(m_events, m_time),
          m_networkMonitor(m_events),
          m_underlay(m_time),
          m_resourceLoader(m_injector->create<ResourceLoader&>()),
          m_sessionManager(m_injector->create<SessionManager&>()),
          m_controlPlaneManager(m_injector->create<ControlPlaneManager&>()),
          m_node(m_injector->create<NodeContext&>())
    {
    }

    ~TailgateVpnPlugin()
    {
        m_sessionManager.StopForegroundMonitor();
        RequestConnectionStop();
        m_controlPlaneManager.StopMaintenance();
        StopDataWorker();
        ResetConnectionAttempt();
        m_node.Stop();
    }

    void Connect(const vpn::VpnChannel& channel)
    {
        winrt::hstring serverText;
        winrt::hstring profileId;
        try
        {
            serverText = Settings::GetString(L"TailgateServer");
            profileId = Settings::GetString(L"ProfileId");
            if (profileId.empty())
            {
                throw winrt::hresult_invalid_argument();
            }
            std::uint64_t callbackGeneration = 0;
            bool rejectConnect = false;
            {
                std::lock_guard lock(m_callbackMutex);
                // Windows Settings can start a new connection without our foreground app.
                // Reject only overlapping teardown; Stop retires the old associated transport.
                rejectConnect = m_disconnectInProgress;
                if (!rejectConnect)
                {
                    callbackGeneration = ++m_callbackGeneration;
                    RequestConnectionStop();
                }
            }
            if (rejectConnect)
            {
                m_logger.LogInfo("suppressing Connect callback during disconnect channel={}",
                                 channel.Id());
                channel.SetErrorMessage(m_resourceLoader.Get(UwpError::Code::ConnectionCancelled));
                return;
            }
            const bool requestedReconnect = m_transportReconnectRequested.exchange(false);
            m_logger.LogDebug("{} channel={} generation={}",
                              requestedReconnect
                                  ? "VpnPlugin.Connect entered after requested transport "
                                    "reconnect"
                                  : "VpnPlugin.Connect entered",
                              channel.Id(),
                              callbackGeneration);
            // A transport loss may produce another Connect call without a preceding Disconnect.
            // Reap the previous control worker and discard only per-session state. Persistent
            // machine, node, and disco keys are loaded again below.
            m_controlPlaneManager.StopMaintenance();
            StopDataWorker();
            ResetConnectionAttempt();
            m_connectionGeneration = m_sessionManager.BeginConnect();
            const bool nativeMode = serverText.empty();
            std::string relayHost;
            std::string relayService;
            if (!nativeMode)
            {
                const foundation::Uri server(serverText);
                if (server.SchemeName() != L"https" || server.Host().empty())
                {
                    throw std::runtime_error("Tailgate expose server must be an HTTPS URL.");
                }
                relayHost = winrt::to_string(server.Host());
                relayService = server.Port() > 0
                                   ? std::format("{}", server.Port())
                                   : winrt::to_string(VpnConstants::Relay::DefaultService);
            }
            m_channel = channel;
            bool supersededByDisconnect = false;
            {
                std::lock_guard lock(m_callbackMutex);
                supersededByDisconnect =
                    callbackGeneration != m_callbackGeneration || m_disconnectInProgress;
                if (!supersededByDisconnect)
                {
                    std::lock_guard stopLock(m_stopMutex);
                    m_connectionStop = std::stop_source{};
                    m_stopConnection = false;
                }
            }
            if (supersededByDisconnect)
            {
                m_logger.LogInfo("connection callback was superseded by disconnect channel={}",
                                 channel.Id());
                channel.SetErrorMessage(m_resourceLoader.Get(UwpError::Code::ConnectionCancelled));
                return;
            }
            m_connectionCancelled = false;
            m_sessionManager.StartForegroundMonitor(winrt::to_string(profileId),
                                                    [this](ForegroundCancellationReason reason)
                                                    {
                                                        CancelConnectionAttempt(reason);
                                                    });
            const bool registered = Settings::GetString(L"RegistrationComplete") == L"true";
            m_controlPlaneManager.LoadIdentity(registered);
            m_nodePrivateKey = m_controlPlaneManager.NodePrivateKey();
            m_discoPrivateKey = m_controlPlaneManager.DiscoPrivateKey();
            const tailgate::wgengine::PeerIdentity identity{
                .NodePrivateKey = m_nodePrivateKey,
                .NodePublicKey = tailgate::crypto::X25519PublicFromPrivate(m_nodePrivateKey),
                .DiscoPrivateKey = m_discoPrivateKey,
            };
            {
                std::lock_guard lock(m_dataPathMutex);
                // Previous workers and packet paths have already been retired.
                m_node.Configure(winrt::to_string(profileId), identity);
            }
            tailgate::control::client::RetryBackoff retryBackoff(InitialConnectMinimumBackoff,
                                                                 InitialConnectMaximumBackoff);
            const auto adapters = NetworkAdapter::Candidates();
            std::size_t nextAdapter = 0;
            bool transportAssociationStarted = false;
            while (!m_stopConnection)
            {
                std::optional<DataPlaneProbe> probe;
                try
                {
                    m_networkInterface = adapters[nextAdapter++ % adapters.size()];
                    m_controlPlaneManager.Start(m_connectionGeneration, m_networkInterface);
                    if (m_stopConnection)
                    {
                        m_controlPlaneManager.RequestStop();
                        break;
                    }
                    m_node.DataPlane().Start(m_connectionGeneration);
                    const std::string authKey =
                        registered ? std::string{}
                                   : winrt::to_string(Settings::GetString(L"AuthKey"));
                    ReportSession(SessionComponent::ControlPlane, SessionEventKind::Connecting);
                    tailgate::control::client::RegistrationResult registration =
                        m_controlPlaneManager.Connect(authKey);
                    if (!registration.Network)
                    {
                        throw std::runtime_error(
                            "Control registration completed without a network map.");
                    }
                    tailgate::types::netmap::NetworkConfig config =
                        std::move(*registration.Network);
                    m_nodePublicKey = m_controlPlaneManager.NodePublicKey();
                    ReportSession(SessionComponent::ControlPlane, SessionEventKind::Ready);
                    m_sessionManager.Notify(m_connectionGeneration,
                                            ForegroundConnectionNotification{
                                                .Kind = ForegroundConnectionKind::ControlAuthorized,
                                                .Url = {},
                                                .ProfileId = winrt::to_string(profileId),
                                            });

                    m_exitNode = winrt::to_string(Settings::GetString(L"ExitNode"));
                    m_node.ExitNode().LoadPending(config, m_exitNode);
                    if (!m_exitNode.empty() && !config.FindExitNode(m_exitNode, false))
                    {
                        m_logger.LogWarning(
                            "configured exit node is unavailable; falling back to none: {}",
                            m_exitNode);
                        m_exitNode.clear();
                        Settings::SetString(L"ExitNode", L"");
                        Settings::SetString(L"ExitNodeSelection", L"");
                    }
                    m_hostedConnection =
                        std::make_unique<HostedConnection>(m_injector, m_node.HostedClient());
                    StartNative(config, nativeMode);
                    if (!nativeMode)
                    {
                        probe = m_node.DataPlane().Probe(winrt::to_string(serverText),
                                                         relayHost,
                                                         relayService,
                                                         m_networkInterface,
                                                         ConnectionCancellation());
                        if (probe->UsingCachedEndpoint)
                        {
                            m_logger.LogInfo("using cached relay resolution name={} address={}",
                                             probe->ValidationHost,
                                             probe->ConnectAddress);
                        }
                        const tailgate::control::client::HostInfo hostInfo = BuildHostInfo();
                        tailgate::hosted::ConnectionResult hosted =
                            m_node.HostedConnection().Connect(tailgate::hosted::ConnectionOptions{
                                .Socket =
                                    tailgate::types::nettype::TcpSocketOptions{
                                        .ConnectAddress = probe->ConnectAddress,
                                        .Service = probe->Service,
                                        .NetworkInterface = m_networkInterface,
                                        .TlsServerName = probe->ValidationHost,
                                        .IoTimeout = 40s,
                                        .ConnectTimeout = std::nullopt,
                                        .ReadinessToken = RelayToken,
                                        .AllowTls13 = false,
                                        .NonBlockingAfterConnect = true,
                                        .Cancellation = ConnectionCancellation(),
                                        .ReadinessEvents = std::ref(*m_events),
                                    },
                                .HttpHost = std::format("{}:{}", relayHost, relayService),
                                .Hostname = hostInfo.Hostname(),
                                .OperatingSystem = hostInfo.OperatingSystem(),
                                .OperatingSystemVersion = hostInfo.OperatingSystemVersion(),
                                .Client =
                                    tailgate::hosted::ClientConfig{
                                        .NodePrivateKey = m_nodePrivateKey,
                                        .NodePublicKey = m_nodePublicKey,
                                        .DiscoPrivateKey = m_discoPrivateKey,
                                        .Network = config,
                                        .ExitNode = m_exitNode,
                                    },
                            });
                        VerifyOrStoreRelayIdentity(serverText, hosted.RelayPublicKey);
                        m_node.DataPlane().RememberProbe(winrt::to_string(serverText), *probe);
                        // Every packet from this node transits the Tailgate relay, so ping results
                        // report that host (its first DNS label) as the relay rather than a peer's
                        // DERP region.
                        m_relayName = relayHost.substr(0, relayHost.find('.'));
                        m_hostedConnection->Start(std::move(hosted), m_exitNode, m_relayName);
                        m_logger.LogDebug("relay network map sent");
                        m_node.DataPlane().Connect();
                    }
                    m_preparation = std::make_unique<tailgate::hosted::Recovery>(
                        m_injector->create<tailgate::types::nettype::TcpSocketFactory&>(),
                        *m_events,
                        m_time);
                    m_switchingNode = std::make_unique<tailgate::ipn::ipnlocal::SwitchingNode>(
                        m_nativeConnection->Node(),
                        m_hostedConnection->Node(),
                        *m_preparation,
                        m_time,
                        nativeMode ? tailgate::ipn::ipnlocal::NodeMode::Native
                                   : tailgate::ipn::ipnlocal::NodeMode::Hosted,
                        tailgate::wgengine::tstun::DeviceOptions{.Name = {},
                                                                 .ReadinessToken = {.Value = 4}},
                        m_exitNode);
                    tailgate::hosted::ConnectionOptions modeOptions;
                    modeOptions.Socket.NetworkInterface = m_networkInterface;
                    modeOptions.Socket.ReadinessToken = RelayToken;
                    modeOptions.Socket.ReadinessEvents = std::ref(*m_events);
                    modeOptions.Socket.AllowTls13 = false;
                    modeOptions.Socket.NonBlockingAfterConnect = true;
                    modeOptions.Socket.IoTimeout = 40s;
                    const auto modeHost = BuildHostInfo();
                    modeOptions.Hostname = modeHost.Hostname();
                    modeOptions.OperatingSystem = modeHost.OperatingSystem();
                    modeOptions.OperatingSystemVersion = modeHost.OperatingSystemVersion();
                    modeOptions.Client = {.NodePrivateKey = m_nodePrivateKey,
                                          .NodePublicKey = m_nodePublicKey,
                                          .DiscoPrivateKey = m_discoPrivateKey,
                                          .Network = config,
                                          .ExitNode = m_exitNode};
                    m_modeRequests = std::make_unique<ModeRequests>(
                        m_node.Modes(), *m_switchingNode, std::move(modeOptions));
                    m_logger.LogDebug("writing app state");
                    m_sessionManager.WriteState(config);
                    m_logger.LogDebug("starting VPN channel");
                    ReportSession(SessionComponent::Platform, SessionEventKind::Connecting);
                    transportAssociationStarted = true;
                    m_channelAdapter.Open(channel, ConnectionCancellation());
                    StartChannel(channel, config);
                    m_networkMonitor.ExcludeAddress(config.SelfAddress());
                    m_underlay.Start(m_networkMonitor.Current(), m_networkInterface);
                    StartDataWorker();
                    ReportSession(SessionComponent::Platform, SessionEventKind::Ready);
                    m_logger.LogDebug("VPN channel started");
                    {
                        std::lock_guard lock(m_dataPathMutex);
                        m_node.ExitNode().CommitPending(m_exitNode);
                    }
                    Settings::Remove(L"NetworkPolicyRestartRequired");
                    m_sessionManager.StopForegroundMonitor();
                    m_controlPlaneManager.StartMaintenance(
                        [this](tailgate::types::netmap::NetworkConfig update)
                        {
                            ApplyControlUpdate(std::move(update));
                        });
                    // Registration and channel startup succeeded; retain this logical profile
                    // for reconnect even when it has no relay.
                    Settings::SetString(L"ProfileValidated", L"true");
                    m_sessionManager.SignalStateChanged();
                    m_logger.LogInfo("VPN connected mode={} exit-node-enabled={}",
                                     nativeMode ? "native" : "hosted",
                                     !m_exitNode.empty());
                    return;
                }
                catch (const winrt::hresult_error& error)
                {
                    if (m_stopConnection)
                    {
                        break;
                    }
                    if (probe && probe->UsingCachedEndpoint)
                    {
                        m_node.DataPlane().InvalidateProbe(winrt::to_string(serverText));
                        m_logger.LogWarning(
                            "discarded cached relay resolution after connection failure");
                    }
                    m_logger.LogError("VPN connection attempt failed hresult={} message={}",
                                      error.code(),
                                      error.message());
                    if (transportAssociationStarted)
                    {
                        m_sessionManager.StopForegroundMonitor();
                        ResetConnectionAttempt();
                        channel.SetErrorMessage(
                            m_resourceLoader.Get(UwpError::Code::VpnProfileDidNotConnect));
                        m_logger.LogWarning(
                            "ending the current Connect callback after an associated "
                            "transport failed; Windows may start a fresh callback");
                        return;
                    }
                }
                catch (const std::exception& error)
                {
                    if (m_stopConnection)
                    {
                        break;
                    }
                    if (probe && probe->UsingCachedEndpoint)
                    {
                        m_node.DataPlane().InvalidateProbe(winrt::to_string(serverText));
                        m_logger.LogWarning(
                            "discarded cached relay resolution after connection failure");
                    }
                    m_logger.LogError("VPN connection attempt failed: {}", error.what());
                    if (transportAssociationStarted)
                    {
                        m_sessionManager.StopForegroundMonitor();
                        ResetConnectionAttempt();
                        channel.SetErrorMessage(
                            m_resourceLoader.Get(UwpError::Code::VpnProfileDidNotConnect));
                        m_logger.LogWarning(
                            "ending the current Connect callback after an associated "
                            "transport failed; Windows may start a fresh callback");
                        return;
                    }
                }
                ResetConnectionAttempt();
                const std::chrono::milliseconds retryDelay = retryBackoff.NextDelay();
                m_logger.LogInfo("retrying VPN connection in {}ms", retryDelay.count());
                if (!WaitForRetry(retryDelay))
                {
                    break;
                }
            }
            m_sessionManager.StopForegroundMonitor();
            ResetConnectionAttempt();
            if (m_connectionCancelled)
            {
                channel.SetErrorMessage(m_resourceLoader.Get(UwpError::Code::ConnectionCancelled));
                m_logger.LogInfo("connection attempt ended after foreground cancellation");
            }
        }
        catch (const winrt::hresult_error& error)
        {
            m_sessionManager.StopForegroundMonitor();
            m_logger.LogError("WinRT error code={} message={}", error.code(), error.message());
            if (!profileId.empty())
            {
                m_sessionManager.Notify(m_connectionGeneration,
                                        ForegroundConnectionNotification{
                                            .Kind = ForegroundConnectionKind::Failed,
                                            .Url = {},
                                            .ProfileId = winrt::to_string(profileId),
                                            .ErrorCode = UwpError::Code::VpnProfileDidNotConnect,
                                        });
            }
            channel.SetErrorMessage(m_resourceLoader.Get(UwpError::Code::VpnProfileDidNotConnect));
            m_logger.LogDebug("terminating failed VPN connection attempt");
            channel.TerminateConnection(
                m_resourceLoader.Get(UwpError::Code::VpnProfileDidNotConnect));
        }
        catch (const std::exception& error)
        {
            m_sessionManager.StopForegroundMonitor();
            m_logger.LogError("{}", error.what());
            if (!profileId.empty())
            {
                m_sessionManager.Notify(m_connectionGeneration,
                                        ForegroundConnectionNotification{
                                            .Kind = ForegroundConnectionKind::Failed,
                                            .Url = {},
                                            .ProfileId = winrt::to_string(profileId),
                                            .ErrorCode = UwpError::Code::VpnProfileDidNotConnect,
                                        });
            }
            channel.SetErrorMessage(m_resourceLoader.Get(UwpError::Code::VpnProfileDidNotConnect));
            m_logger.LogDebug("terminating failed VPN connection attempt");
            channel.TerminateConnection(
                m_resourceLoader.Get(UwpError::Code::VpnProfileDidNotConnect));
        }
    }

    void Disconnect(const vpn::VpnChannel& channel)
    {
        {
            std::lock_guard lock(m_callbackMutex);
            ++m_callbackGeneration;
            m_disconnectInProgress = true;
            RequestConnectionStop();
        }
        m_sessionManager.BeginStop();
        m_controlPlaneManager.StopMaintenance();
        StopDataWorker();
        {
            std::lock_guard lock(m_dataPathMutex);
            m_logger.LogDebug("VpnPlugin.Disconnect entered channel={}", channel.Id());
            m_node.Stop();
            m_controlPlaneManager.Reset();
        }
        // Keep the associated outer transport alive until Stop disassociates and closes it. If the
        // plug-in releases the transport first, RS2 may treat that as an unexpected transport loss
        // and dispatch a concurrent reconnect while this disconnect is still in progress.
        m_logger.LogDebug("calling VpnChannel.Stop channel={}", channel.Id());
        try
        {
            channel.Stop();
            m_logger.LogDebug("VpnChannel.Stop returned");
        }
        catch (const winrt::hresult_error& error)
        {
            m_logger.LogWarning(
                "VpnChannel.Stop failed hresult={} message={}", error.code(), error.message());
        }
        {
            std::lock_guard lock(m_dataPathMutex);
            m_modeRequests.reset();
            m_switchingNode.reset();
            m_preparation.reset();
            m_nativeConnection.reset();
            m_hostedConnection.reset();
            m_node.ResetTransport();
            m_channelAdapter.Close();
        }
        m_sessionManager.CompleteStop();
        m_sessionManager.SignalStateChanged();
        {
            std::lock_guard lock(m_callbackMutex);
            m_disconnectInProgress = false;
        }
    }

    void GetKeepAlivePayload(const vpn::VpnChannel& channel, vpn::VpnPacketBuffer& packet)
    {
        packet = nullptr;
        if (!m_stopConnection)
        {
            m_channelAdapter.KeepAlive(channel, packet);
        }
    }

    void Encapsulate(const vpn::VpnChannel&,
                     const vpn::VpnPacketBufferList& packets,
                     const vpn::VpnPacketBufferList& output)
    {
        if (!m_stopConnection)
        {
            m_channelAdapter.Encapsulate(packets, output);
        }
    }

    void Decapsulate(const vpn::VpnChannel& channel,
                     const vpn::VpnPacketBuffer&,
                     const vpn::VpnPacketBufferList& packets,
                     const vpn::VpnPacketBufferList&)
    {
        if (!m_stopConnection)
        {
            m_channelAdapter.Decapsulate(channel, packets);
        }
    }

private:
    void ReportSession(SessionComponent component, SessionEventKind kind)
    {
        m_sessionManager.Report(SessionEvent{
            .Generation = m_connectionGeneration,
            .Component = component,
            .Kind = kind,
        });
    }

    [[nodiscard]] bool WaitForRetry(std::chrono::milliseconds delay) const
    {
        std::unique_lock lock(m_retryMutex);
        return !m_retryChanged.wait_for(lock,
                                        delay,
                                        [this]()
                                        {
                                            return m_stopConnection.load();
                                        });
    }

    void RequestConnectionStop()
    {
        std::stop_source source(std::nostopstate);
        {
            std::lock_guard lock(m_stopMutex);
            m_stopConnection = true;
            source = m_connectionStop;
        }
        source.request_stop();
        m_events->Wake();
        m_retryChanged.notify_all();
    }

    std::stop_token ConnectionCancellation()
    {
        std::lock_guard lock(m_stopMutex);
        return m_connectionStop.get_token();
    }

    void ResetConnectionAttempt()
    {
        if (m_dataWorker.joinable())
        {
            StopDataWorker();
        }
        m_controlPlaneManager.Reset();
        std::lock_guard lock(m_dataPathMutex);
        m_node.HostedClient().Stop();
        m_modeRequests.reset();
        m_switchingNode.reset();
        m_preparation.reset();
        m_nativeConnection.reset();
        m_pendingMap.reset();
        m_hostedConnection.reset();
        m_node.ResetTransport();
        m_channelAdapter.Close();
    }

    void CancelConnectionAttempt(ForegroundCancellationReason reason)
    {
        m_connectionCancelled = true;
        RequestConnectionStop();
        m_controlPlaneManager.RequestStop();
        m_logger.LogInfo(
            "{}",
            reason == ForegroundCancellationReason::ForegroundExited
                ? "foreground process exited during connection; cancelling the background attempt"
                : "foreground dismissed authorization; cancelling the background attempt");
        // Socket setup and blocking bootstrap I/O observe m_connectionStop.
    }

    void ApplyControlUpdate(tailgate::types::netmap::NetworkConfig update)
    {
        std::lock_guard lock(m_dataPathMutex);
        // Both backends serialize maps with crypto and local-service processing.
        m_pendingMap = std::move(update);
        m_events->Wake();
    }

    void RequestTransportReconnect(ReconnectReason reason)
    {
        if (m_transportReconnectRequested.exchange(true))
        {
            return;
        }
        m_switchingNode->CancelTransition(
            tailgate::ipn::ipnlocal::TransitionFailure::PolicyChanged);
        Settings::SetString(L"NetworkPolicyRestartRequired", L"true");
        m_logger.LogInfo("VPN host policy requires profile reconnect reason={}",
                         static_cast<int>(reason));
        // Socket retirement cannot change RS2 routes or DNS. The existing foreground
        // profile controller performs this explicit disconnect/connect operation.
        // Keep the current channel useful until that operation is actually requested.
        m_sessionManager.SignalStateChanged();
    }

    void StopDataWorker()
    {
        RequestConnectionStop();
        if (m_dataWorker.joinable())
        {
            m_dataWorker.join();
        }
    }

    void StartDataWorker()
    {
        std::lock_guard lock(m_callbackMutex);
        const auto generation = m_callbackGeneration;
        m_dataWorker = std::thread(
            [this, generation]
            {
                RunDataWorker(generation);
            });
    }

    static FireAndForget EndFailedChannel(winrt::com_ptr<TailgateVpnPlugin> owner,
                                          vpn::VpnChannel channel,
                                          std::uint64_t generation)
    {
        co_await winrt::resume_background();
        try
        {
            {
                std::lock_guard lock(owner->m_callbackMutex);
                if (generation != owner->m_callbackGeneration)
                {
                    co_return;
                }
            }
            channel.TerminateConnection(
                owner->m_resourceLoader.Get(UwpError::Code::VpnProfileDidNotConnect));
        }
        catch (...)
        {
            owner->m_logger.LogWarning("failed to end VPN channel: {}", winrt::to_message());
        }
    }

    void StartNative(const tailgate::types::netmap::NetworkConfig& config, bool enabled)
    {
        m_relayName.clear();
        m_nativeConnection = std::make_unique<NativeConnection>(
            m_injector, m_networkInterface, m_nodePrivateKey, m_nodePublicKey);
        tailgate::net::Endpoint endpoint;
        if (enabled)
        {
            endpoint = m_nativeConnection->Open(ConnectionCancellation());
            m_controlPlaneManager.PublishEndpoints(
                m_nativeConnection->DiscoverEndpoints(config, endpoint, ConnectionCancellation()));
        }
        tailgate::wgengine::SessionOptions options;
        options.NodePrivateKey = m_nodePrivateKey;
        options.NodePublicKey = m_nodePublicKey;
        options.DiscoPrivateKey = m_discoPrivateKey;
        options.AdvertisedEndpoint = endpoint;
        options.ExitNode = m_exitNode;
        m_nativeConnection->Start(config, std::move(options), enabled);
        if (enabled)
        {
            ReportSession(SessionComponent::DataPlane, SessionEventKind::Ready);
        }
    }

    tailgate::ipn::ipnlocal::NodeBackend& Backend()
    {
        return *m_switchingNode;
    }

    PacketDevice& Device()
    {
        return m_nativeConnection->Device();
    }

    void PublishEndpoints(const tailgate::ipn::ipnlocal::NativeEndpoints& endpoints)
    {
        if (!m_nativeConnection)
        {
            return;
        }
        try
        {
            const auto local = m_nativeConnection->LocalEndpoint(endpoints.BoundEndpoint);
            const auto& discovered = endpoints.PublicEndpoint;
            m_nativeConnection->Session().SetAdvertisedEndpoint(discovered.value_or(local));
            std::vector<tailgate::control::client::MapEndpoint> published;
            if (discovered)
            {
                published.push_back({.AddressPort = discovered->ToString(),
                                     .Type = tailgate::control::client::EndpointType::Stun});
            }
            published.push_back({.AddressPort = local.ToString(),
                                 .Type = tailgate::control::client::EndpointType::Local});
            m_controlPlaneManager.PublishEndpoints(std::move(published));
            m_logger.LogInfo("native UDP endpoints updated; VPN channel retained");
        }
        catch (const NetworkAdapterUnavailable&)
        {
            m_logger.LogWarning("bound adapter disappeared before endpoint publication");
        }
    }

    void FlushLocal()
    {
        std::vector<std::vector<std::uint8_t>> local;
        m_node.DataPlane().FlushLocal(local);
        std::lock_guard lock(m_dataPathMutex);
        m_channelAdapter.QueueOutput(std::move(local));
        m_channelAdapter.QueueOutput(Device().DrainOutput());
    }

    void UpdateUnderlay()
    {
        using tailgate::ipn::ipnlocal::NodeMode;
        const bool native = m_switchingNode->Transition().Effective == NodeMode::Native;
        const bool ready = native ? m_nativeConnection->Node().Connected() : Backend().Ready();
        if (const auto change = m_underlay.Poll(m_networkMonitor.Current(), ready))
        {
            const auto selected = change->Network ? change->Network->Interface : std::nullopt;
            m_switchingNode->ChangeNetwork(selected);
            m_controlPlaneManager.PublishEndpoints({});
            if (!change->Network)
            {
                m_nativeConnection->SuspendNetwork();
                m_hostedConnection->Node().RetireTransport();
                m_hostedConnection->CancelRecovery();
                return;
            }
            m_networkInterface = change->Network->Interface.value_or(std::string{});
            m_controlPlaneManager.ChangeNetwork(m_networkInterface);
            m_modeRequests->ChangeNetwork(m_networkInterface);
            m_nativeConnection->ChangeNetwork(m_networkInterface);

            m_logger.LogInfo("replacing network sockets generation={}; retaining VPN channel",
                             change->Generation);
        }
        m_nativeConnection->PollResolution();
    }

    void RunDataWorker(std::uint64_t generation)
    {
        ThreadApartment::Ensure();
        try
        {
            while (!m_stopConnection)
            {
                std::optional<tailgate::types::netmap::NetworkConfig> update;
                std::vector<std::vector<std::uint8_t>> input;
                {
                    std::lock_guard lock(m_dataPathMutex);
                    if (m_channelAdapter.Failed())
                    {
                        throw std::system_error(std::make_error_code(std::errc::network_down));
                    }
                    update = std::exchange(m_pendingMap, std::nullopt);
                    input = m_channelAdapter.TakeInput(MaximumPacketsPerTurn);
                }
                UpdateUnderlay();
                auto& node = Backend();
                if (update)
                {
                    node.UpdateNetwork(std::move(*update));
                    m_sessionManager.WriteState(node.Network());
                    if (m_channelPolicy !=
                        ChannelPolicy::Build(node.Network(), !m_exitNode.empty()))
                    {
                        RequestTransportReconnect(ReconnectReason::NetworkPolicyUpdate);
                    }
                }
                bool reconnect = false;
                for (auto& packet : input)
                {
                    EncapsulationContext context{.Original = packet,
                                                 .Node = node,
                                                 .RelayName = m_relayName,
                                                 .ExitNode = m_exitNode};
                    m_node.DataPlane().Encapsulate(context);
                    reconnect |= context.ReconnectRequested;
                    if (context.Handled)
                    {
                        continue;
                    }
                    const auto queued = Device().QueueInput(std::move(packet));
                    if (queued == PacketQueueResult::Closed)
                    {
                        throw std::system_error(std::make_error_code(std::errc::not_connected));
                    }
                    if (queued == PacketQueueResult::Full)
                    {
                        m_logger.LogWarning("host packet queue is full; dropping packet");
                    }
                }
                m_modeRequests->Poll();
                FlushLocal();
                if (reconnect)
                {
                    RequestTransportReconnect(ReconnectReason::ExitNodeChange);
                }
                const auto completed = node.Wait(MaximumPacketsPerTurn,
                                                 MaximumPacketsPerTurn,
                                                 VpnConstants::Channel::MaximumFrameSize);
                if (completed.Endpoints)
                {
                    PublishEndpoints(*completed.Endpoints);
                }
                if (completed.DataPathReady)
                {
                    ReportSession(SessionComponent::DataPlane, SessionEventKind::Ready);
                }
                if (completed.NetworkChanged)
                {
                    m_sessionManager.WriteState(node.Network());
                    if (m_channelPolicy !=
                        ChannelPolicy::Build(node.Network(), !m_exitNode.empty()))
                    {
                        RequestTransportReconnect(ReconnectReason::NetworkPolicyUpdate);
                    }
                }
                for (const auto& received : completed.Received)
                {
                    if (received.Ping)
                    {
                        m_node.Pings().Complete(*received.Ping,
                                                received.DirectSource.has_value(),
                                                received.DirectSource
                                                    ? received.DirectSource->ToString()
                                                    : std::string{});
                    }
                }
                m_modeRequests->Poll();
                FlushLocal();
            }
        }
        catch (...)
        {
            if (!m_stopConnection)
            {
                m_logger.LogError("VPN node worker failed: {}", winrt::to_message());
                RequestConnectionStop();
                EndFailedChannel(get_strong(), m_channel, generation);
            }
        }
    }

    void VerifyOrStoreRelayIdentity(const winrt::hstring& server,
                                    const tailgate::crypto::Bytes32& publicKey)
    {
        // The HTTPS certificate authenticates the server, so a rotated relay node key (for
        // example after the relay recreated its identity) is only worth a notice.
        const std::string encoded =
            tailgate::crypto::BytesToHex(publicKey.data(), publicKey.size());
        if (Settings::GetString(L"PinnedRelayServer") == server)
        {
            const std::string pinned =
                winrt::to_string(Settings::GetString(L"PinnedRelayPublicKey"));
            if (!pinned.empty() && pinned != encoded)
            {
                m_logger.LogInfo("Tailgate server node key changed; trusting the TLS certificate");
            }
        }
        Settings::SetString(L"PinnedRelayServer", server);
        Settings::SetString(L"PinnedRelayPublicKey", winrt::to_hstring(encoded));
    }

    void StartChannel(const vpn::VpnChannel& channel,
                      const tailgate::types::netmap::NetworkConfig& config)
    {
        m_channelPolicy = ChannelPolicy::Build(config, !m_exitNode.empty());
        m_channelAdapter.Start(channel, m_channelPolicy);
    }

    static constexpr tailgate::base::EventToken RelayToken{.Value = 2};
    static constexpr std::size_t MaximumPacketsPerTurn = 64;
    PluginInjector m_injector;
    std::shared_ptr<tailgate::base::EventLoop> m_events;
    tailgate::base::TimeProvider& m_time;
    ChannelAdapter m_channelAdapter;
    NetworkMonitor m_networkMonitor;
    tailgate::ipn::ipnlocal::UnderlaySelection m_underlay;
    std::mutex m_stopMutex;
    std::stop_source m_connectionStop;
    std::thread m_dataWorker;
    std::string m_networkInterface;
    ResourceLoader& m_resourceLoader;
    SessionManager& m_sessionManager;
    ControlPlaneManager& m_controlPlaneManager;
    NodeContext& m_node;
    SessionGeneration m_connectionGeneration = 0;
    std::atomic_bool m_stopConnection = false;
    mutable std::mutex m_retryMutex;
    mutable std::condition_variable m_retryChanged;
    std::atomic_bool m_connectionCancelled = false;
    std::atomic_bool m_transportReconnectRequested = false;
    std::mutex m_callbackMutex;
    std::uint64_t m_callbackGeneration = 0;
    bool m_disconnectInProgress = false;
    vpn::VpnChannel m_channel{nullptr};
    tailgate::crypto::Bytes32 m_discoPrivateKey{};
    std::unique_ptr<HostedConnection> m_hostedConnection;
    std::unique_ptr<NativeConnection> m_nativeConnection;
    std::unique_ptr<tailgate::hosted::Recovery> m_preparation;
    std::unique_ptr<tailgate::ipn::ipnlocal::SwitchingNode> m_switchingNode;
    std::unique_ptr<ModeRequests> m_modeRequests;
    std::optional<tailgate::types::netmap::NetworkConfig> m_pendingMap;
    std::recursive_mutex m_dataPathMutex;
    ChannelPolicy m_channelPolicy;
    tailgate::crypto::Bytes32 m_nodePrivateKey{};
    tailgate::crypto::Bytes32 m_nodePublicKey{};
    std::string m_exitNode;
    std::string m_relayName;
    tailgate::base::Logger m_logger{"uwp-vpn"};
};

} // namespace

vpn::IVpnPlugIn CreateTailgateVpnPlugin()
{
    return winrt::make<TailgateVpnPlugin>();
}

} // namespace tailgate::uwp
