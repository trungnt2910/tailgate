#include "TailgateVpnPlugin.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <format>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Networking.Sockets.h>
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
#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/net/packet/Tsmp.h>
#include <tailgate/wgengine/wireguard/Router.h>

#include "common/AuthorizationState.h"
#include "common/HostInfo.h"
#include "common/ResourceLoader.h"
#include "common/Settings.h"
#include "common/UwpError.h"
#include "common/UwpTcpStream.h"
#include "common/VpnConstants.h"

#include "service/ExitNodeService.h"

#include "DI.h"

namespace tailgate::uwp
{
namespace
{

namespace foundation = winrt::Windows::Foundation;
namespace networking = winrt::Windows::Networking;
namespace sockets = winrt::Windows::Networking::Sockets;
namespace streams = winrt::Windows::Storage::Streams;
namespace vpn = winrt::Windows::Networking::Vpn;
using namespace bg;
using namespace bg::manager;
using namespace bg::service;
using namespace std::chrono_literals;

// VpnChannel::Start requires this declaration and has no capacity query. Actual buffers are
// requested from VpnChannel and bounded by their reported capacity in AppendRelayPackets.
constexpr std::chrono::seconds InitialConnectMinimumBackoff(1);
constexpr std::chrono::seconds InitialConnectMaximumBackoff(30);
enum class ReconnectReason
{
    NetworkPolicyUpdate,
    ExitNodeChange,
};

std::string NormalizeDnsName(std::string name)
{
    while (!name.empty() && name.back() == '.')
    {
        name.pop_back();
    }
    return name;
}

bool IsDnsNamespace(const std::string& name)
{
    const std::string normalized = NormalizeDnsName(name);
    if (normalized.empty() || normalized.size() > 253)
    {
        return false;
    }
    std::size_t start = 0;
    while (start < normalized.size())
    {
        const std::size_t dot = normalized.find('.', start);
        const std::size_t end = dot == std::string::npos ? normalized.size() : dot;
        if (end == start || end - start > 63)
        {
            return false;
        }
        for (std::size_t index = start; index < end; ++index)
        {
            const unsigned char character = static_cast<unsigned char>(normalized[index]);
            if (!std::isalnum(character) && character != '-' && character != '_')
            {
                return false;
            }
        }
        start = end + 1;
    }
    return true;
}

vpn::VpnDomainNameAssignment
BuildDomainAssignment(const tailgate::types::netmap::NetworkConfig& config)
{
    vpn::VpnDomainNameAssignment assignment;
    std::vector<std::string> assignedNames;
    const auto append = [&](const std::string& name,
                            vpn::VpnDomainNameType type,
                            const std::vector<std::string>& resolverNames)
    {
        const std::string normalized = NormalizeDnsName(name);
        if (!IsDnsNamespace(normalized) ||
            std::find(assignedNames.begin(), assignedNames.end(), normalized) !=
                assignedNames.end())
        {
            return;
        }
        auto dnsServers = winrt::single_threaded_vector<networking::HostName>();
        if (resolverNames.empty())
        {
            dnsServers.Append(networking::HostName(VpnConstants::Network::ServiceHost));
        }
        else
        {
            for (const std::string& resolver : resolverNames)
            {
                dnsServers.Append(networking::HostName(winrt::to_hstring(resolver)));
            }
        }
        assignment.DomainNameList().Append(
            vpn::VpnDomainNameInfo(winrt::to_hstring(normalized), type, dnsServers, nullptr));
        assignedNames.push_back(normalized);
    };

    for (const tailgate::types::netmap::NetworkConfig::DnsRoute& route : config.DnsRoutes)
    {
        append(route.Suffix, vpn::VpnDomainNameType::Suffix, route.Resolvers);
    }
    for (const std::string& domain : config.DnsDomains)
    {
        append(domain, vpn::VpnDomainNameType::Suffix, {});
    }
    return assignment;
}

void FillPacket(const vpn::VpnPacketBuffer& packet,
                const std::vector<std::uint8_t>& bytes,
                const foundation::IInspectable& transportContext = nullptr)
{
    const streams::Buffer buffer = packet.Buffer();
    if (bytes.size() > buffer.Capacity())
    {
        throw std::runtime_error("UWP VPN packet exceeds packet buffer capacity.");
    }
    std::copy(bytes.begin(), bytes.end(), buffer.data());
    buffer.Length(static_cast<std::uint32_t>(bytes.size()));
    if (transportContext != nullptr)
    {
        packet.TransportContext(transportContext);
    }
}

void AppendPacket(const vpn::VpnChannel& channel,
                  const vpn::VpnPacketBufferList& packets,
                  vpn::VpnDataPathType type,
                  const std::vector<std::uint8_t>& bytes)
{
    vpn::VpnPacketBuffer packet{nullptr};
    channel.RequestVpnPacketBuffer(type, packet);
    FillPacket(packet, bytes);
    packets.Append(packet);
}

void AppendRelayPackets(const vpn::VpnChannel& channel,
                        const vpn::VpnPacketBufferList& packets,
                        const std::vector<std::uint8_t>& bytes)
{
    std::size_t offset = 0;
    while (offset < bytes.size())
    {
        vpn::VpnPacketBuffer packet{nullptr};
        channel.RequestVpnPacketBuffer(vpn::VpnDataPathType::Send, packet);
        const std::size_t capacity = packet.Buffer().Capacity();
        if (capacity == 0)
        {
            throw std::runtime_error("UWP returned a zero-capacity VPN packet buffer.");
        }
        const std::size_t size = std::min(capacity, bytes.size() - offset);
        FillPacket(
            packet,
            std::vector<std::uint8_t>(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                      bytes.begin() + static_cast<std::ptrdiff_t>(offset + size)));
        packets.Append(packet);
        offset += size;
    }
}

struct TailgateVpnPlugin : winrt::implements<TailgateVpnPlugin, vpn::IVpnPlugIn>
{
    TailgateVpnPlugin()
        : m_injector(CreateRs2PluginInjector()),
          m_resourceLoader(m_injector.create<ResourceLoader&>()),
          m_sessionManager(m_injector.create<SessionManager&>()),
          m_controlPlaneManager(m_injector.create<ControlPlaneManager&>()),
          m_dataPlaneManager(m_injector.create<DataPlaneManager&>()),
          m_transportManager(m_injector.create<TransportManager&>()),
          m_pingService(m_injector.create<PingService&>()),
          m_exitNodeService(m_injector.create<ExitNodeService&>())
    {
        (void)m_injector.create<HostedDnsService&>();
        (void)m_injector.create<NetworkService&>();
    }

    ~TailgateVpnPlugin()
    {
        m_sessionManager.StopForegroundMonitor();
        m_stopConnection = true;
        m_controlPlaneManager.StopMaintenance();
    }

    void Connect(const vpn::VpnChannel& channel)
    {
        winrt::hstring serverText;
        try
        {
            serverText = Settings::GetString(L"TailgateServer");
            const bool foregroundConnectionRequested =
                !serverText.empty() && ConnectionCancellationMonitor(serverText).Available();
            std::uint64_t callbackGeneration = 0;
            bool rejectConnect = false;
            bool disconnectInProgress = false;
            {
                std::lock_guard lock(m_callbackMutex);
                disconnectInProgress = m_disconnectInProgress;
                rejectConnect = disconnectInProgress ||
                                (m_suppressAutomaticReconnect && !foregroundConnectionRequested);
                if (!rejectConnect)
                {
                    m_suppressAutomaticReconnect = false;
                    callbackGeneration = ++m_callbackGeneration;
                    m_stopConnection = true;
                }
            }
            if (rejectConnect)
            {
                m_logger.LogInfo("suppressing Connect callback during or after explicit disconnect "
                                 "channel={} disconnecting={} foreground-request={}",
                                 channel.Id(),
                                 disconnectInProgress,
                                 foregroundConnectionRequested);
                channel.SetErrorMessage(m_resourceLoader.Get(UwpError::Code::ConnectionCancelled));
                return;
            }
            const bool requestedReconnect = m_transportReconnectRequested.exchange(false);
            m_logger.LogDebug("{}",
                              requestedReconnect
                                  ? "VpnPlugin.Connect entered after requested transport "
                                    "reconnect"
                                  : "VpnPlugin.Connect entered");
            // A transport loss may produce another Connect call without a preceding Disconnect.
            // Reap the previous control worker and discard only per-session state. Persistent
            // machine, node, and disco keys are loaded again below.
            m_controlPlaneManager.StopMaintenance();
            ResetConnectionAttempt();
            m_connectionGeneration = m_sessionManager.BeginConnect();
            if (serverText.empty())
            {
                throw std::runtime_error("Tailgate expose server is missing.");
            }
            const foundation::Uri server(serverText);
            if (server.SchemeName() != L"https" || server.Host().empty())
            {
                throw std::runtime_error("Tailgate expose server must be an HTTPS URL.");
            }
            const std::string relayHost = winrt::to_string(server.Host());
            const std::string relayService =
                server.Port() > 0 ? std::format("{}", server.Port())
                                  : winrt::to_string(VpnConstants::Relay::DefaultService);
            m_channel = channel;
            bool supersededByDisconnect = false;
            {
                std::lock_guard lock(m_callbackMutex);
                supersededByDisconnect =
                    callbackGeneration != m_callbackGeneration || m_disconnectInProgress;
                if (!supersededByDisconnect)
                {
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
            m_sessionManager.StartForegroundMonitor(winrt::to_string(serverText),
                                                    [this](ForegroundCancellationReason reason)
                                                    {
                                                        CancelConnectionAttempt(reason);
                                                    });
            const bool registered = Settings::GetString(L"RegistrationComplete") == L"true";
            m_controlPlaneManager.LoadIdentity(registered);
            m_nodePrivateKey = m_controlPlaneManager.NodePrivateKey();
            m_discoPrivateKey = m_controlPlaneManager.DiscoPrivateKey();
            tailgate::control::client::RetryBackoff retryBackoff(InitialConnectMinimumBackoff,
                                                                 InitialConnectMaximumBackoff);
            bool transportAssociationStarted = false;
            while (!m_stopConnection)
            {
                std::optional<DataPlaneProbe> probe;
                try
                {
                    m_controlPlaneManager.Start(m_connectionGeneration);
                    m_dataPlaneManager.Start(m_connectionGeneration);
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
                                                .TailgateServer = winrt::to_string(serverText),
                                            });

                    probe = m_dataPlaneManager.Probe(
                        winrt::to_string(serverText), relayHost, relayService);
                    if (probe->UsingCachedEndpoint)
                    {
                        m_logger.LogInfo("using cached relay resolution name={} address={}",
                                         probe->ValidationHost,
                                         probe->ConnectAddress);
                    }
                    m_relaySocket = sockets::StreamSocket();
                    // VpnChannel requires an unconnected transport and returns E_INVALIDARG if
                    // AssociateTransport is called after ConnectAsync. Keep this before
                    // UwpTcpStream construction: that constructor connects and upgrades this same
                    // StreamSocket to TLS.
                    m_logger.LogDebug("associating unconnected relay transport");
                    transportAssociationStarted = true;
                    const TransportId transportId = m_transportManager.Resolve(
                        TransportTarget{.Kind = TransportTargetKind::Tailgate});
                    m_logger.LogDebug("assigning RS2 relay transport id={}", transportId.Value);
                    channel.AssociateTransport(m_relaySocket, nullptr);
                    m_relayRawStream =
                        std::make_unique<UwpTcpStream>(m_relaySocket,
                                                       probe->ConnectAddress,
                                                       probe->Service,
                                                       sockets::SocketProtectionLevel::Tls12,
                                                       40s,
                                                       probe->ValidationHost);
                    m_relayDecoder.Feed(tailgate::hosted::RequestHttpUpgrade(
                        *m_relayRawStream, std::format("{}:{}", relayHost, relayService)));
                    tailgate::hosted::Frame challengeFrame =
                        tailgate::hosted::ReadFrame(*m_relayRawStream, m_relayDecoder);
                    if (challengeFrame.Type != tailgate::hosted::MessageType::ServerChallenge)
                    {
                        throw std::runtime_error(
                            "Tailgate server did not provide an identity challenge.");
                    }
                    const tailgate::hosted::Challenge challenge =
                        tailgate::hosted::DecodeChallenge(challengeFrame.Payload);
                    VerifyOrStoreRelayIdentity(serverText, challenge.RelayPublicKey);

                    tailgate::hosted::Authentication authentication;
                    authentication.Tailnet = config.Domain;
                    authentication.NodeId = config.SelfNodeId;
                    authentication.Hostname = BuildHostInfo().Hostname;
                    authentication.OperatingSystem = BuildHostInfo().OperatingSystem;
                    authentication.OperatingSystemVersion = BuildHostInfo().OperatingSystemVersion;
                    authentication.NodePublicKey = m_controlPlaneManager.NodePublicKey();
                    authentication.ClientNonce = tailgate::crypto::GeneratePrivateKey();
                    authentication.ClientProof =
                        tailgate::hosted::CreateClientProof(m_nodePrivateKey,
                                                            challenge.RelayPublicKey,
                                                            challenge.ServerNonce,
                                                            authentication.ClientNonce);
                    tailgate::hosted::WriteFrame(
                        *m_relayRawStream,
                        tailgate::hosted::Frame{
                            .Type = tailgate::hosted::MessageType::Authenticate,
                            .Payload = tailgate::hosted::EncodeAuthentication(authentication)});
                    m_logger.LogDebug("relay authentication sent; waiting for response");
                    const tailgate::hosted::Frame response =
                        tailgate::hosted::ReadFrame(*m_relayRawStream, m_relayDecoder);
                    m_logger.LogDebug("relay authentication response type={} payload-bytes={}",
                                      static_cast<std::uint16_t>(response.Type),
                                      response.Payload.size());
                    if (response.Type == tailgate::hosted::MessageType::Rejected)
                    {
                        throw std::runtime_error(std::format(
                            "Tailgate server rejected authentication: {}.",
                            tailgate::hosted::DecodeRejection(response.Payload).Reason));
                    }
                    if (response.Type != tailgate::hosted::MessageType::Authenticated)
                    {
                        throw std::runtime_error(
                            "Tailgate server returned an invalid authentication response.");
                    }
                    const tailgate::hosted::Session session =
                        tailgate::hosted::DecodeSession(response.Payload);
                    const tailgate::crypto::Bytes32 expectedProof =
                        tailgate::hosted::CreateServerProof(m_nodePrivateKey,
                                                            challenge.RelayPublicKey,
                                                            challenge.ServerNonce,
                                                            authentication.ClientNonce);
                    if (session.Tailnet != config.Domain ||
                        !tailgate::hosted::ProofMatches(expectedProof, session.ServerProof))
                    {
                        throw std::runtime_error("Tailgate server identity proof is invalid.");
                    }
                    m_dataPlaneManager.RememberProbe(winrt::to_string(serverText), *probe);
                    m_nodePublicKey = authentication.NodePublicKey;
                    m_config = config;
                    m_exitNode = winrt::to_string(Settings::GetString(L"ExitNode"));
                    m_exitNodeService.LoadPending(config, m_exitNode);
                    if (!m_exitNode.empty() &&
                        !tailgate::types::netmap::FindExitNode(config.Peers, m_exitNode, false))
                    {
                        m_logger.LogWarning(
                            "configured exit node is unavailable; falling back to none: {}",
                            m_exitNode);
                        m_exitNode.clear();
                        Settings::SetString(L"ExitNode", L"");
                        Settings::SetString(L"ExitNodeSelection", L"");
                    }
                    m_router = std::make_unique<tailgate::wgengine::wireguard::WireGuardRouter>(
                        m_nodePrivateKey, config.Peers, m_exitNode);
                    m_disco = std::make_unique<tailgate::disco::Disco>(m_discoPrivateKey,
                                                                       m_nodePublicKey);
                    m_pendingRelayFrames.clear();
                    // Every packet from this node transits the Tailgate relay, so ping results
                    // report that host (its first DNS label) as the relay rather than a peer's DERP
                    // region.
                    m_relayName = relayHost.substr(0, relayHost.find('.'));
                    m_logger.LogDebug("sending relay network map peers={}", config.Peers.size());
                    tailgate::hosted::WriteFrame(
                        *m_relayRawStream,
                        tailgate::hosted::Frame{.Type = tailgate::hosted::MessageType::NetworkMap,
                                                .Payload =
                                                    tailgate::hosted::EncodeNetworkConfig(config)});
                    m_logger.LogDebug("relay network map sent");
                    m_dataPlaneManager.Connect();
                    m_logger.LogDebug("writing app state");
                    m_sessionManager.WriteState(config);
                    m_logger.LogDebug("starting VPN channel");
                    ReportSession(SessionComponent::Platform, SessionEventKind::Connecting);
                    StartChannel(channel, config);
                    ReportSession(SessionComponent::Platform, SessionEventKind::Ready);
                    m_logger.LogDebug("VPN channel started");
                    {
                        std::lock_guard lock(m_dataPathMutex);
                        m_exitNodeService.CommitPending(m_exitNode);
                    }
                    Settings::Remove(L"NetworkPolicyRestartRequired");
                    m_sessionManager.StopForegroundMonitor();
                    m_controlPlaneManager.StartMaintenance(
                        [this](tailgate::types::netmap::NetworkConfig update)
                        {
                            ApplyControlUpdate(std::move(update));
                        });
                    // Both the control registration and the relay data path are up, so the stored
                    // server is known-good and the app may skip the sign-in page on the next
                    // launch.
                    Settings::SetString(L"ProfileValidated", L"true");
                    m_sessionManager.SignalStateChanged();
                    m_logger.LogInfo("VPN connected through Tailgate server {}", relayHost);
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
                        m_dataPlaneManager.InvalidateProbe(winrt::to_string(serverText));
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
                            m_resourceLoader.Get(UwpError::Code::RelayConnectionFailed));
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
                        m_dataPlaneManager.InvalidateProbe(winrt::to_string(serverText));
                        m_logger.LogWarning(
                            "discarded cached relay resolution after connection failure");
                    }
                    m_logger.LogError("VPN connection attempt failed: {}", error.what());
                    if (transportAssociationStarted)
                    {
                        m_sessionManager.StopForegroundMonitor();
                        ResetConnectionAttempt();
                        channel.SetErrorMessage(
                            m_resourceLoader.Get(UwpError::Code::RelayConnectionFailed));
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
            if (!serverText.empty())
            {
                m_sessionManager.Notify(m_connectionGeneration,
                                        ForegroundConnectionNotification{
                                            .Kind = ForegroundConnectionKind::Failed,
                                            .Url = {},
                                            .TailgateServer = winrt::to_string(serverText),
                                            .ErrorCode = UwpError::Code::RelayConnectionFailed,
                                        });
            }
            channel.SetErrorMessage(m_resourceLoader.Get(UwpError::Code::RelayConnectionFailed));
            m_logger.LogDebug("terminating failed VPN connection attempt");
            channel.TerminateConnection(
                m_resourceLoader.Get(UwpError::Code::RelayConnectionFailed));
        }
        catch (const std::exception& error)
        {
            m_sessionManager.StopForegroundMonitor();
            m_logger.LogError("{}", error.what());
            if (!serverText.empty())
            {
                m_sessionManager.Notify(m_connectionGeneration,
                                        ForegroundConnectionNotification{
                                            .Kind = ForegroundConnectionKind::Failed,
                                            .Url = {},
                                            .TailgateServer = winrt::to_string(serverText),
                                            .ErrorCode = UwpError::Code::RelayConnectionFailed,
                                        });
            }
            channel.SetErrorMessage(m_resourceLoader.Get(UwpError::Code::RelayConnectionFailed));
            m_logger.LogDebug("terminating failed VPN connection attempt");
            channel.TerminateConnection(
                m_resourceLoader.Get(UwpError::Code::RelayConnectionFailed));
        }
    }

    void Disconnect(const vpn::VpnChannel& channel)
    {
        const std::uint32_t channelId = channel.Id();
        {
            std::lock_guard lock(m_callbackMutex);
            ++m_callbackGeneration;
            m_disconnectInProgress = true;
            m_suppressAutomaticReconnect = true;
            m_stopConnection = true;
        }
        m_sessionManager.BeginStop();
        m_controlPlaneManager.StopMaintenance();
        {
            std::lock_guard lock(m_dataPathMutex);
            m_logger.LogDebug("VpnPlugin.Disconnect entered channel={}", channelId);
            m_dataPathReady = false;
            m_router.reset();
            m_disco.reset();
            m_pendingRelayFrames.clear();
            m_controlPlaneManager.Reset();
            m_dataPlaneManager.Stop();
            m_transportManager.Reset();
        }
        // Keep the associated outer transport alive until Stop disassociates and closes it. If the
        // plug-in releases the transport first, RS2 may treat that as an unexpected transport loss
        // and dispatch a concurrent reconnect while this disconnect is still in progress.
        const auto stopStarted = std::chrono::steady_clock::now();
        m_logger.LogDebug("calling VpnChannel.Stop channel={}", channelId);
        try
        {
            channel.Stop();
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - stopStarted);
            m_logger.LogDebug(
                "VpnChannel.Stop returned channel={} elapsed-ms={}", channelId, elapsed.count());
        }
        catch (const winrt::hresult_error& error)
        {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - stopStarted);
            m_logger.LogWarning(
                "VpnChannel.Stop failed channel={} elapsed-ms={} hresult={} message={}",
                channelId,
                elapsed.count(),
                error.code(),
                error.message());
        }
        {
            std::lock_guard lock(m_dataPathMutex);
            m_relayRawStream.reset();
            m_relaySocket = nullptr;
        }
        m_sessionManager.CompleteStop();
        {
            std::lock_guard lock(m_callbackMutex);
            m_disconnectInProgress = false;
        }
    }

    void GetKeepAlivePayload(const vpn::VpnChannel& channel, vpn::VpnPacketBuffer& keepAlivePacket)
    {
        try
        {
            std::lock_guard lock(m_dataPathMutex);
            m_logger.LogTrace("keepalive stats encapsulate-calls={} encapsulate-packets={} "
                              "decapsulate-calls={} decapsulate-frames={}",
                              m_encapsulateCalls,
                              m_encapsulatePackets,
                              m_decapsulateCalls,
                              m_decapsulateFrames);
            std::vector<std::uint8_t> payload;
            if (m_router)
            {
                AppendTransportFrames(payload, m_router->UpdateTimers());
            }
            AppendFrame(payload,
                        tailgate::hosted::Frame{.Type = tailgate::hosted::MessageType::Heartbeat,
                                                .Payload = {}});
            channel.RequestVpnPacketBuffer(vpn::VpnDataPathType::Send, keepAlivePacket);
            FillPacket(keepAlivePacket, payload);
        }
        catch (const winrt::hresult_error& error)
        {
            m_logger.LogError(
                "keepalive failed hresult={} message={}", error.code(), error.message());
        }
        catch (const std::exception& error)
        {
            m_logger.LogWarning("keepalive failed: {}", error.what());
        }
        catch (...)
        {
            m_logger.LogError("keepalive failed: unknown exception");
        }
    }

    void Encapsulate(const vpn::VpnChannel& channel,
                     const vpn::VpnPacketBufferList& packets,
                     const vpn::VpnPacketBufferList& encapsulatedPackets)
    {
        try
        {
            bool reconnectAfterEncapsulate = false;
            {
                std::lock_guard lock(m_dataPathMutex);
                ++m_encapsulateCalls;
                // Relay frames queued outside the data path (streamed network-map updates) ride
                // out with this batch.
                std::vector<std::uint8_t> payload = std::move(m_pendingRelayFrames);
                m_pendingRelayFrames.clear();
                if (!m_dataPathReady)
                {
                    AppendFrame(
                        payload,
                        tailgate::hosted::Frame{.Type = tailgate::hosted::MessageType::Heartbeat,
                                                .Payload = {}});
                    m_dataPathReady = true;
                }
                // Every buffer removed from the platform's list must be appended to an output
                // list; dropping one leaks it from the channel's fixed buffer pool, and an
                // exhausted pool permanently stops Encapsulate deliveries.
                std::vector<vpn::VpnPacketBuffer> spentBuffers;
                while (packets.Size() > 0)
                {
                    vpn::VpnPacketBuffer packet = packets.RemoveAtBegin();
                    streams::Buffer buffer = packet.Buffer();
                    if (m_router)
                    {
                        std::vector<std::uint8_t> plaintext(buffer.Length());
                        std::copy(
                            buffer.data(), buffer.data() + buffer.Length(), plaintext.begin());
                        EncapsulationContext context{
                            .Original = plaintext,
                            .Config = m_config,
                            .Disco = m_disco.get(),
                            .Router = m_router.get(),
                            .ExitNode = m_exitNode,
                            .RelayName = m_relayName,
                            .RemoteOutput = payload,
                        };
                        m_dataPlaneManager.Encapsulate(context);
                        reconnectAfterEncapsulate =
                            reconnectAfterEncapsulate || context.ReconnectRequested;
                        ++m_encapsulatePackets;
                    }
                    spentBuffers.push_back(std::move(packet));
                }
                m_logger.LogTrace("encapsulate payload={}", payload.size());
                // Leftover buffers carry a heartbeat frame instead of a zero length: the
                // platform must receive every consumed buffer back, and zero-length encapsulated
                // buffers abort the channel.
                std::vector<std::uint8_t> filler;
                AppendFrame(filler,
                            tailgate::hosted::Frame{
                                .Type = tailgate::hosted::MessageType::Heartbeat, .Payload = {}});
                std::size_t offset = 0;
                for (vpn::VpnPacketBuffer& packet : spentBuffers)
                {
                    streams::Buffer buffer = packet.Buffer();
                    std::size_t size =
                        std::min<std::size_t>(buffer.Capacity(), payload.size() - offset);
                    if (size == 0)
                    {
                        std::copy(filler.begin(), filler.end(), buffer.data());
                        buffer.Length(static_cast<std::uint32_t>(filler.size()));
                        encapsulatedPackets.Append(packet);
                        continue;
                    }
                    std::copy(payload.begin() + static_cast<std::ptrdiff_t>(offset),
                              payload.begin() + static_cast<std::ptrdiff_t>(offset + size),
                              buffer.data());
                    buffer.Length(static_cast<std::uint32_t>(size));
                    encapsulatedPackets.Append(packet);
                    offset += size;
                }
                if (offset < payload.size())
                {
                    AppendRelayPackets(
                        channel,
                        encapsulatedPackets,
                        std::vector<std::uint8_t>(
                            payload.begin() + static_cast<std::ptrdiff_t>(offset), payload.end()));
                }
            }
            if (reconnectAfterEncapsulate)
            {
                RequestTransportReconnect(ReconnectReason::ExitNodeChange);
            }
        }
        catch (const winrt::hresult_error& error)
        {
            m_logger.LogError(
                "encapsulate failed hresult={} message={}", error.code(), error.message());
        }
        catch (const std::exception& error)
        {
            m_logger.LogWarning("encapsulate failed: {}", error.what());
        }
        catch (...)
        {
            m_logger.LogError("encapsulate failed: unknown exception");
        }
    }

    void Decapsulate(const vpn::VpnChannel& channel,
                     const vpn::VpnPacketBuffer& encapsulatedPacket,
                     const vpn::VpnPacketBufferList& decapsulatedPackets,
                     const vpn::VpnPacketBufferList& controlPacketsToSend)
    {
        try
        {
            std::lock_guard lock(m_dataPathMutex);
            ++m_decapsulateCalls;
            streams::Buffer buffer = encapsulatedPacket.Buffer();
            // Relay frames queued outside the data path (streamed network-map updates) ride out
            // with this batch.
            std::vector<std::uint8_t> relayPlaintext = std::move(m_pendingRelayFrames);
            m_pendingRelayFrames.clear();
            std::vector<std::vector<std::uint8_t>> localPackets;
            m_relayDecoder.Feed(buffer.data(), buffer.Length());
            while (std::optional<tailgate::hosted::Frame> frame = m_relayDecoder.Next())
            {
                DecapsulationContext context{
                    .Message = *frame,
                    .Config = m_config,
                    .Disco = m_disco.get(),
                    .Router = m_router.get(),
                    .NodePrivateKey = m_nodePrivateKey,
                    .NodePublicKey = m_nodePublicKey,
                    .ExitNode = m_exitNode,
                    .LocalOutput = localPackets,
                    .RemoteOutput = relayPlaintext,
                };
                m_dataPlaneManager.Decapsulate(context);
                ++m_decapsulateFrames;
            }
            m_dataPlaneManager.FlushLocal(localPackets);
            for (const std::vector<std::uint8_t>& packet : localPackets)
            {
                AppendPacket(channel, decapsulatedPackets, vpn::VpnDataPathType::Receive, packet);
            }
            if (!relayPlaintext.empty())
            {
                AppendRelayPackets(channel, controlPacketsToSend, relayPlaintext);
            }
        }
        catch (const winrt::hresult_error& error)
        {
            m_logger.LogError(
                "decapsulate failed hresult={} message={}", error.code(), error.message());
        }
        catch (const std::exception& error)
        {
            m_logger.LogWarning("decapsulate failed: {}", error.what());
        }
        catch (...)
        {
            m_logger.LogError("decapsulate failed: unknown exception");
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
        constexpr std::chrono::milliseconds RetryWaitSlice{100};
        std::chrono::milliseconds waited{0};
        while (waited < delay && !m_stopConnection)
        {
            const std::chrono::milliseconds slice = std::min(RetryWaitSlice, delay - waited);
            std::this_thread::sleep_for(slice);
            waited += slice;
        }
        return !m_stopConnection;
    }

    void ResetConnectionAttempt()
    {
        m_controlPlaneManager.Reset();
        std::lock_guard lock(m_dataPathMutex);
        m_router.reset();
        m_disco.reset();
        m_relayRawStream.reset();
        if (m_relaySocket)
        {
            try
            {
                m_relaySocket.Close();
            }
            catch (const winrt::hresult_error& error)
            {
                m_logger.LogWarning("relay cleanup failed hresult={}", error.code());
            }
            m_relaySocket = nullptr;
        }
        m_relayDecoder = tailgate::hosted::Decoder{};
        m_pendingRelayFrames.clear();
        m_dataPlaneManager.Reset();
        m_dataPathReady = false;
    }

    void CancelConnectionAttempt(ForegroundCancellationReason reason)
    {
        m_connectionCancelled = true;
        m_stopConnection = true;
        m_controlPlaneManager.RequestStop();
        m_logger.LogInfo(
            "{}",
            reason == ForegroundCancellationReason::ForegroundExited
                ? "foreground process exited during connection; cancelling the background attempt"
                : "foreground dismissed authorization; cancelling the background attempt");
        std::lock_guard lock(m_dataPathMutex);
        if (m_relaySocket)
        {
            try
            {
                m_relaySocket.Close();
            }
            catch (const winrt::hresult_error& error)
            {
                m_logger.LogWarning(
                    "failed to close relay transport during connection cancellation hresult={}",
                    error.code());
            }
        }
    }

    void ApplyControlUpdate(tailgate::types::netmap::NetworkConfig update)
    {
        {
            std::lock_guard lock(m_dataPathMutex);
            if (update.Domain != m_config.Domain || update.SelfNodeId != m_config.SelfNodeId ||
                update.SelfKey != m_config.SelfKey)
            {
                throw ControlIdentityChangedError();
            }
            // Compare against the policy actually installed on VpnChannel, not merely the
            // previous netmap. If closing the outer transport fails, a later copy of the same
            // netmap must still retry the policy reconnect.
            const bool networkPolicyChanged = NetworkPolicyChanged(m_channelConfig, update);
            m_config = std::move(update);
            if (m_router)
            {
                m_router->UpdatePeers(m_config.Peers, m_exitNode);
            }
            m_sessionManager.WriteState(m_config);
            // The relay host keeps its own copy of this node's peer table; without this frame it
            // would go stale and drop traffic from newly joined or rekeyed peers until the next
            // reconnect (the Linux frontend queues the same frame). Relay frames can only leave
            // through the data-path callbacks, so it is queued for the next Encapsulate or
            // Decapsulate rather than written here.
            AppendFrame(m_pendingRelayFrames,
                        tailgate::hosted::Frame{
                            .Type = tailgate::hosted::MessageType::NetworkMap,
                            .Payload = tailgate::hosted::EncodeNetworkConfig(m_config)});
            m_logger.LogDebug("applied streamed network-map update peers={} queued-relay-bytes={}",
                              m_config.Peers.size(),
                              m_pendingRelayFrames.size());
            if (!networkPolicyChanged)
            {
                return;
            }
        }
        RequestTransportReconnect(ReconnectReason::NetworkPolicyUpdate);
    }

    void RequestTransportReconnect(ReconnectReason reason)
    {
        std::lock_guard lock(m_dataPathMutex);
        if (!m_relaySocket)
        {
            throw std::runtime_error(
                "The VPN relay transport is unavailable for a policy reconnect.");
        }
        m_logger.LogInfo(
            "{}",
            reason == ReconnectReason::NetworkPolicyUpdate
                ? "network-map policy changed; closing the outer transport for reconnect"
                : "exit node changed; closing the outer transport for reconnect");
        m_transportReconnectRequested = true;
        m_dataPathReady = false;
        try
        {
            m_relaySocket.Close();
        }
        catch (...)
        {
            m_transportReconnectRequested = false;
            throw;
        }
        m_stopConnection = true;
        m_controlPlaneManager.RequestStop();
    }

    static void AppendFrame(std::vector<std::uint8_t>& output, const tailgate::hosted::Frame& frame)
    {
        std::vector<std::uint8_t> encoded = tailgate::hosted::Encode(frame);
        output.insert(output.end(), encoded.begin(), encoded.end());
    }

    static void AppendTransportFrames(
        std::vector<std::uint8_t>& output,
        std::vector<tailgate::wgengine::wireguard::WireGuardRouter::TransportPacket> packets)
    {
        for (auto& packet : packets)
        {
            AppendFrame(
                output,
                tailgate::hosted::Frame{
                    .Type = tailgate::hosted::MessageType::ClientPacket,
                    .Payload = tailgate::hosted::EncodePeerPacket(tailgate::hosted::PeerPacket{
                        .Peer = packet.Peer,
                        .Payload = std::move(packet.Payload),
                        .Control = packet.Control,
                    }),
                });
        }
    }

    [[nodiscard]] std::vector<tailgate::net::packet::Ipv4Prefix>
    Ipv4InclusionPrefixes(const tailgate::types::netmap::NetworkConfig& config) const
    {
        constexpr tailgate::net::packet::Ipv4Prefix tailnet{
            .Network = VpnConstants::Network::TailnetIpv4Network,
            .PrefixLength = VpnConstants::Network::TailnetIpv4PrefixLength,
        };
        std::vector<tailgate::net::packet::Ipv4Prefix> result{
            tailnet,
            tailgate::net::packet::Ipv4Prefix{
                .Network = VpnConstants::Network::ServiceIpv4Address,
                .PrefixLength = VpnConstants::Network::HostIpv4PrefixLength,
            },
        };
        if (!m_exitNode.empty())
        {
            result.push_back(tailgate::net::packet::Ipv4Prefix{
                .Network = VpnConstants::Network::LowerDefaultIpv4Network,
                .PrefixLength = VpnConstants::Network::SplitDefaultPrefixLength,
            });
            result.push_back(tailgate::net::packet::Ipv4Prefix{
                .Network = VpnConstants::Network::UpperDefaultIpv4Network,
                .PrefixLength = VpnConstants::Network::SplitDefaultPrefixLength,
            });
        }

        const auto append = [&](const tailgate::net::packet::Ipv4Prefix& prefix)
        {
            const auto duplicate =
                std::find_if(result.begin(),
                             result.end(),
                             [&](const tailgate::net::packet::Ipv4Prefix& existing)
                             {
                                 return existing.Network == prefix.Network &&
                                        existing.PrefixLength == prefix.PrefixLength;
                             });
            if (duplicate == result.end())
            {
                result.push_back(prefix);
            }
        };
        for (const tailgate::types::netmap::PeerConfig& peer : config.Peers)
        {
            for (const tailgate::net::packet::Ipv4Prefix& prefix : peer.AllowedPrefixes)
            {
                if (prefix.PrefixLength == 0 ||
                    (prefix.PrefixLength >= tailnet.PrefixLength &&
                     tailgate::net::packet::Contains(tailnet, prefix.Network)))
                {
                    continue;
                }
                append(prefix);
            }
        }
        std::sort(result.begin(),
                  result.end(),
                  [](const tailgate::net::packet::Ipv4Prefix& left,
                     const tailgate::net::packet::Ipv4Prefix& right)
                  {
                      return left.Network < right.Network ||
                             (left.Network == right.Network &&
                              left.PrefixLength < right.PrefixLength);
                  });
        return result;
    }

    [[nodiscard]] vpn::VpnRouteAssignment
    BuildRouteAssignment(const tailgate::types::netmap::NetworkConfig& config) const
    {
        const std::vector<tailgate::net::packet::Ipv4Prefix> prefixes =
            Ipv4InclusionPrefixes(config);
        auto routes = winrt::single_threaded_vector<vpn::VpnRoute>();
        for (const tailgate::net::packet::Ipv4Prefix& prefix : prefixes)
        {
            const std::string address = tailgate::net::packet::FormatIpv4(prefix.Network);
            routes.Append(vpn::VpnRoute(networking::HostName(winrt::to_hstring(address)),
                                        prefix.PrefixLength));
            m_logger.LogDebug(
                "installing IPv4 inclusion route {}/{}", address, prefix.PrefixLength);
        }

        vpn::VpnRouteAssignment assignment;
        assignment.Ipv4InclusionRoutes(routes);
        assignment.ExcludeLocalSubnets(true);
        return assignment;
    }

    bool NetworkPolicyChanged(const tailgate::types::netmap::NetworkConfig& previous,
                              const tailgate::types::netmap::NetworkConfig& next) const
    {
        const auto routeSignature = [](const tailgate::types::netmap::NetworkConfig& config)
        {
            std::vector<std::string> result;
            for (const tailgate::types::netmap::NetworkConfig::DnsRoute& route : config.DnsRoutes)
            {
                std::string signature = route.Suffix;
                for (const std::string& resolver : route.Resolvers)
                {
                    signature += "\n" + resolver;
                }
                result.push_back(std::move(signature));
            }
            return result;
        };
        const std::vector<tailgate::net::packet::Ipv4Prefix> previousPrefixes =
            Ipv4InclusionPrefixes(previous);
        const std::vector<tailgate::net::packet::Ipv4Prefix> nextPrefixes =
            Ipv4InclusionPrefixes(next);
        const bool ipv4RoutesChanged =
            previousPrefixes.size() != nextPrefixes.size() ||
            !std::equal(previousPrefixes.begin(),
                        previousPrefixes.end(),
                        nextPrefixes.begin(),
                        [](const tailgate::net::packet::Ipv4Prefix& left,
                           const tailgate::net::packet::Ipv4Prefix& right)
                        {
                            return left.Network == right.Network &&
                                   left.PrefixLength == right.PrefixLength;
                        });
        return previous.SelfAddress != next.SelfAddress ||
               previous.SelfAddresses != next.SelfAddresses ||
               previous.DnsDomains != next.DnsDomains ||
               routeSignature(previous) != routeSignature(next) || ipv4RoutesChanged;
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
        auto assignedIpv4 = winrt::single_threaded_vector<networking::HostName>();
        assignedIpv4.Append(networking::HostName(winrt::to_hstring(config.SelfAddress)));
        auto assignedIpv6 = winrt::single_threaded_vector<networking::HostName>();
        for (const std::string& address : config.SelfAddresses)
        {
            if (address.find(':') != std::string::npos)
            {
                assignedIpv6.Append(networking::HostName(winrt::to_hstring(address)));
            }
        }
        const auto ipv6 = assignedIpv6.Size() == 0 ? nullptr : assignedIpv6.GetView();
        channel.StartWithMainTransport(assignedIpv4.GetView(),
                                       ipv6,
                                       nullptr,
                                       BuildRouteAssignment(config),
                                       BuildDomainAssignment(config),
                                       VpnConstants::Channel::Mtu,
                                       VpnConstants::Channel::MaximumFrameSize,
                                       false,
                                       m_relaySocket);
        m_channelConfig = config;
    }

    PluginInjector m_injector;
    ResourceLoader& m_resourceLoader;
    SessionManager& m_sessionManager;
    ControlPlaneManager& m_controlPlaneManager;
    DataPlaneManager& m_dataPlaneManager;
    TransportManager& m_transportManager;
    PingService& m_pingService;
    ExitNodeService& m_exitNodeService;
    SessionGeneration m_connectionGeneration = 0;
    sockets::StreamSocket m_relaySocket{nullptr};
    std::atomic_bool m_stopConnection = false;
    std::atomic_bool m_connectionCancelled = false;
    std::atomic_bool m_transportReconnectRequested = false;
    std::mutex m_callbackMutex;
    std::uint64_t m_callbackGeneration = 0;
    bool m_disconnectInProgress = false;
    bool m_suppressAutomaticReconnect = false;
    vpn::VpnChannel m_channel{nullptr};
    tailgate::crypto::Bytes32 m_discoPrivateKey{};
    std::unique_ptr<UwpTcpStream> m_relayRawStream;
    std::recursive_mutex m_dataPathMutex;
    tailgate::hosted::Decoder m_relayDecoder;
    std::unique_ptr<tailgate::wgengine::wireguard::WireGuardRouter> m_router;
    std::unique_ptr<tailgate::disco::Disco> m_disco;
    tailgate::types::netmap::NetworkConfig m_config;
    tailgate::types::netmap::NetworkConfig m_channelConfig;
    tailgate::crypto::Bytes32 m_nodePrivateKey{};
    tailgate::crypto::Bytes32 m_nodePublicKey{};
    std::string m_exitNode;
    std::vector<std::uint8_t> m_pendingRelayFrames;
    std::string m_relayName;
    bool m_dataPathReady = false;
    std::uint64_t m_encapsulateCalls = 0;
    std::uint64_t m_encapsulatePackets = 0;
    std::uint64_t m_decapsulateCalls = 0;
    std::uint64_t m_decapsulateFrames = 0;
    tailgate::base::Logger m_logger{"uwp-vpn"};
};

} // namespace

vpn::IVpnPlugIn CreateTailgateVpnPlugin()
{
    return winrt::make<TailgateVpnPlugin>();
}

} // namespace tailgate::uwp
