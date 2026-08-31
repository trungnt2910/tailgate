// libc++ 22 implements C++20 syncstream behind this opt-in. It must be enabled before
// any standard-library header includes libc++'s configuration.
#define _LIBCPP_ENABLE_EXPERIMENTAL

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <deque>
#include <exception>
#include <filesystem>
#include <format>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <syncstream>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/route.h>
#include <netdb.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/di.hpp>

#include <tailgate/PlatformFrontend.h>
#include <tailgate/base/Logging.h>
#include <tailgate/cli/Arguments.h>
#include <tailgate/control/client/Connection.h>
#include <tailgate/control/client/RetryBackoff.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/derp/Client.h>
#include <tailgate/derp/Connection.h>
#include <tailgate/disco/Disco.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/Connection.h>
#include <tailgate/hosted/DiscoProbes.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/hosted/ServerSession.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/net/packet/Tsmp.h>
#include <tailgate/qr/QrCode.h>
#include <tailgate/serve/FunnelConfig.h>
#include <tailgate/serve/acme/Client.h>
#include <tailgate/types/nettype/TcpSocket.h>
#include <tailgate/wgengine/Engine.h>
#include <tailgate/wgengine/Session.h>
#include <tailgate/wgengine/magicsock/Connection.h>
#include <tailgate/wgengine/magicsock/PeerPathState.h>
#include <tailgate/wgengine/router/Config.h>
#include <tailgate/wgengine/wireguard/Router.h>

#include "DI.h"
#include "DataplaneEvents.h"
#include "DirectConnection.h"
#include "FileChangeWaiter.h"
#include "Files.h"
#include "HostedClient.h"
#include "HostedConnectionRegistry.h"
#include "Lifecycle.h"
#include "Network.h"
#include "PeerApiServer.h"
#include "PingIpc.h"
#include "ProcessWait.h"
#include "QrCode.h"
#include "Registration.h"
#include "RelayServer.h"
#include "State.h"
#include "StatusWriter.h"
#include "UniqueFd.h"

namespace
{

using tailgate::linux_frontend::Lifecycle;

void HandleStopSignal(int)
{
    Lifecycle::RequestStop();
}

void HandleReloadSignal(int)
{
    Lifecycle::RequestReload();
}

void HandleStartupSignal(int)
{
    Lifecycle::InterruptStartup();
}

using tailgate::linux_frontend::DefaultRouteInterface;

constexpr int ExposeLocalPort = 41113;
constexpr std::chrono::minutes ReloadWaitTimeout{2};
constexpr std::chrono::minutes ProcessExitTimeout{1};

void PrintFunnelAvailability(const tailgate::linux_frontend::DaemonStatus& status,
                             const tailgate::cli::FunnelOptions& options,
                             bool background)
{
    const std::string magicName = status.Domain.empty()
                                      ? status.Hostname
                                      : std::format("{}.{}", status.Hostname, status.Domain);
    const std::string port = options.Port == 443 ? "" : std::format(":{}", options.Port);
    std::cout << "Available on the internet:\n\n";
    std::cout << std::format("https://{}{}/\n", magicName, port);
    std::cout << std::format("|-- proxy http://127.0.0.1:{}\n\n", options.LocalPort);
    if (background)
    {
        std::cout << "Funnel started and running in the background.\n";
        std::cout << std::format("To disable the proxy, run: tailgate funnel --https={} off\n",
                                 options.Port);
    }
    else
    {
        std::cout << "Press Ctrl+C to exit.\n";
    }
}

tailgate::linux_frontend::DaemonStatus RequireRunningDaemon()
{
    const auto existing = tailgate::linux_frontend::ReadDaemonStatus();
    if (!existing || !tailgate::linux_frontend::IsProcessRunning(existing->ProcessId))
    {
        throw std::runtime_error("Tailgate is not running");
    }
    return *existing;
}

void ReloadDaemon(pid_t pid)
{
    if (kill(pid, SIGUSR1) != 0)
    {
        throw std::runtime_error("failed to reload Tailgate settings");
    }
}

tailgate::linux_frontend::DaemonStatus
WaitForDaemonReload(pid_t pid, const std::string& ignoredError = {}, bool interruptible = false)
{
    const std::uint64_t targetRevision = tailgate::linux_frontend::ReadSettings()
                                             .value_or(tailgate::linux_frontend::SettingsState{})
                                             .Revision;
    tailgate::linux_frontend::FileChangeWaiter changes(tailgate::linux_frontend::StateDirectory());
    const auto deadline = std::chrono::steady_clock::now() + ReloadWaitTimeout;
    tailgate::linux_frontend::DaemonStatus latest;
    while (true)
    {
        if (interruptible && Lifecycle::Stopping())
        {
            throw std::runtime_error("settings update interrupted");
        }
        latest = RequireRunningDaemon();
        if (latest.ProcessId != pid)
        {
            throw std::runtime_error("Tailgate daemon restarted during reload");
        }
        if (latest.ConfigurationRevision < targetRevision)
        {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now());
            if (!changes.WaitForChange(
                    tailgate::linux_frontend::DaemonStatusFileName, remaining, interruptible))
            {
                break;
            }
            continue;
        }
        if (!latest.Error.empty() && latest.Error != ignoredError)
        {
            throw std::runtime_error(latest.Error);
        }
        if (latest.Online)
        {
            return latest;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (!changes.WaitForChange(
                tailgate::linux_frontend::DaemonStatusFileName, remaining, interruptible))
        {
            break;
        }
    }
    if (interruptible && Lifecycle::Stopping())
    {
        throw std::runtime_error("settings update interrupted");
    }
    if (!latest.Error.empty())
    {
        throw std::runtime_error(latest.Error);
    }
    throw std::runtime_error("Tailgate daemon did not finish applying settings");
}

std::string AccidentalUpMessage(const tailgate::linux_frontend::SettingsState& settings)
{
    std::string command = "\n\n        tailgate up";
    if (!settings.ExitNode.empty())
    {
        command += std::format(" --exit-node={}", settings.ExitNode);
    }
    if (!settings.AcceptDns)
    {
        command += " --accept-dns=false";
    }
    if (!settings.TailgateUrl.empty())
    {
        command += std::format(" --tailgate={}", settings.TailgateUrl);
    }
    return std::format("changing settings via 'tailgate up' requires mentioning all\n"
                       "non-default flags. To proceed, either re-run your command with --reset or\n"
                       "use the command below to explicitly mention the current value of\n"
                       "all non-default settings:{}",
                       command);
}

tailgate::linux_frontend::SettingsState
ApplyUpOptions(const tailgate::linux_frontend::SettingsState& current,
               const tailgate::cli::UpOptions& options)
{
    const bool anyPreference = options.HostnameSet || options.AcceptDnsSet || options.ExitNodeSet ||
                               options.TailgateUrlSet || options.Reset;
    if (!anyPreference)
    {
        return current;
    }
    if (!options.Reset && ((!options.ExitNodeSet && !current.ExitNode.empty()) ||
                           (!options.AcceptDnsSet && !current.AcceptDns) ||
                           (!options.TailgateUrlSet && !current.TailgateUrl.empty())))
    {
        throw std::runtime_error(AccidentalUpMessage(current));
    }
    tailgate::linux_frontend::SettingsState result = current;
    result.ExitNode = options.ExitNodeSet ? options.ExitNode : "";
    result.AcceptDns = options.AcceptDnsSet ? options.AcceptDns : true;
    result.TailgateUrl = options.TailgateUrlSet ? options.TailgateUrl : "";
    if (options.HostnameSet)
    {
        result.Hostname = options.Hostname;
    }
    return result;
}

std::string ResolveAuthKey(const std::string& value)
{
    if (value.empty())
    {
        return {};
    }
    if (value.rfind("file:", 0) == 0)
    {
        if (value.size() == 5)
        {
            throw std::runtime_error("--auth-key=file: requires a path");
        }
        return tailgate::linux_frontend::ReadTextFile(value.substr(5));
    }
    return value;
}

std::string CurrentLocale()
{
    for (const char* name : {"LC_ALL", "LC_CTYPE", "LANG"})
    {
        if (const char* value = std::getenv(name); value != nullptr && value[0] != '\0')
        {
            return value;
        }
    }
    return "C";
}

void PrintAuthorizationPrompt(const std::string& authorizationUrl,
                              const std::string& backendState,
                              const tailgate::cli::UpOptions& options)
{
    if (backendState == "NeedsMachineAuth")
    {
        std::cerr << "\nTo approve your machine, visit (as admin):\n\n\t" << authorizationUrl
                  << "\n\n";
    }
    else
    {
        std::cerr << "\nTo authenticate, visit:\n\n\t" << authorizationUrl << "\n\n";
    }
    if (!options.Qr)
    {
        return;
    }
    const tailgate::qr::QrCode code = tailgate::qr::QrCode::Encode(authorizationUrl);
    const tailgate::linux_frontend::QrTextFormat format =
        tailgate::linux_frontend::ResolveQrTextFormat(options.QrFormat, CurrentLocale());
    std::cerr << tailgate::linux_frontend::RenderQrCode(code, format) << '\n';
}

int RunDown()
{
    const auto existing = tailgate::linux_frontend::ReadDaemonStatus();
    if (existing && tailgate::linux_frontend::IsProcessRunning(existing->ProcessId))
    {
        if (kill(existing->ProcessId, SIGTERM) != 0)
        {
            throw std::runtime_error("failed to signal the Tailgate daemon");
        }
        if (!tailgate::linux_frontend::WaitForProcessExit(existing->ProcessId, ProcessExitTimeout))
        {
            throw std::runtime_error("Tailgate did not stop after SIGTERM");
        }
    }
    tailgate::linux_frontend::RestoreResolverConfiguration();
    tailgate::linux_frontend::RemoveResolverBackup();
    tailgate::linux_frontend::RemoveDaemonStatus();
    return 0;
}

int RunLogout()
{
    const std::optional<tailgate::linux_frontend::IdentityState> identity =
        tailgate::linux_frontend::ReadIdentity();
    RunDown();
    if (!identity)
    {
        tailgate::linux_frontend::RemoveProfileState();
        return 0;
    }

    tailgate::control::client::HostInfo host;
    if (!identity->Hostname.empty())
    {
        host.SetHostname(identity->Hostname);
    }
    tailgate::di::Injector injector;
    tailgate::linux_frontend::InstallBindings(injector);
    tailgate::control::client::ConnectionFactory& factory =
        injector.create<tailgate::control::client::ConnectionFactory&>();
    std::unique_ptr<tailgate::control::client::Connection> control =
        factory.CreateConnection(tailgate::control::client::SessionOptions{
            .Host = std::move(host),
            .MachinePrivateKey = identity->MachinePrivateKey,
            .NodePrivateKey = identity->NodePrivateKey,
            .ExternalNodePublicKey = std::nullopt,
            .NetworkInterface = DefaultRouteInterface(),
            .ReadinessToken = {},
        });
    control->Logout();
    tailgate::linux_frontend::RemoveProfileState();
    return 0;
}

tailgate::platform::UpResult RunUp(const tailgate::cli::UpOptions& options)
{
    tailgate::linux_frontend::RemoveLegacyHostedProfiles();
    const tailgate::linux_frontend::SettingsState currentSettings =
        tailgate::linux_frontend::ReadSettings().value_or(
            tailgate::linux_frontend::SettingsState{});
    tailgate::linux_frontend::SettingsState requestedSettings =
        ApplyUpOptions(currentSettings, options);
    if (!requestedSettings.TailgateUrl.empty() && requestedSettings.ExposePort != 0)
    {
        throw std::runtime_error(
            "this node is running expose; stop expose before enabling --tailgate");
    }
    const auto existing = tailgate::linux_frontend::ReadDaemonStatus();
    if (existing && tailgate::linux_frontend::IsProcessRunning(existing->ProcessId))
    {
        const bool restartWithAuth =
            !options.AuthKey.empty() &&
            (!existing->Error.empty() || !existing->AuthorizationUrl.empty() ||
             requestedSettings.TailgateUrl != currentSettings.TailgateUrl);
        tailgate::linux_frontend::WriteSettings(requestedSettings);
        if (restartWithAuth)
        {
            tailgate::base::Log(tailgate::base::LogLevel::Info,
                                "daemon",
                                "restarting failed connection with a supplied auth key");
            if (kill(existing->ProcessId, SIGTERM) != 0)
            {
                throw std::runtime_error("failed to restart the Tailgate daemon");
            }
            if (!tailgate::linux_frontend::WaitForProcessExit(existing->ProcessId,
                                                              ProcessExitTimeout))
            {
                throw std::runtime_error("Tailgate did not stop for relay recovery");
            }
            tailgate::linux_frontend::RemoveDaemonStatus();
        }
        else
        {
            if (!existing->AuthorizationUrl.empty())
            {
                PrintAuthorizationPrompt(
                    existing->AuthorizationUrl, existing->BackendState, options);
            }
            if (kill(existing->ProcessId, SIGUSR1) == 0)
            {
                (void)WaitForDaemonReload(static_cast<pid_t>(existing->ProcessId), existing->Error);
                return tailgate::platform::UpResult{.Ready = true};
            }
            tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                "daemon",
                                "stale Tailgate status; starting a new daemon");
            tailgate::linux_frontend::RemoveDaemonStatus();
        }
    }

    tailgate::linux_frontend::RestoreResolverConfiguration();
    tailgate::linux_frontend::SaveResolverConfiguration();

    tailgate::control::client::HostInfo host;
    if (!requestedSettings.Hostname.empty())
    {
        host.SetHostname(requestedSettings.Hostname);
    }
    const std::string authKey = ResolveAuthKey(options.AuthKey);
    std::optional<tailgate::linux_frontend::IdentityState> identity =
        tailgate::linux_frontend::ReadIdentity();
    if (identity && requestedSettings.Hostname.empty() && !identity->Hostname.empty())
    {
        host.SetHostname(identity->Hostname);
    }
    if (!identity)
    {
        identity = tailgate::linux_frontend::IdentityState{
            .MachinePrivateKey = tailgate::crypto::GeneratePrivateKey(),
            .NodePrivateKey = tailgate::crypto::GeneratePrivateKey(),
            .DiscoPrivateKey = tailgate::crypto::GeneratePrivateKey(),
            .Hostname = host.Hostname()};
        tailgate::linux_frontend::WriteIdentity(*identity);
    }
    else
    {
        bool identityChanged = false;
        if (std::all_of(identity->DiscoPrivateKey.begin(),
                        identity->DiscoPrivateKey.end(),
                        [](std::uint8_t byte)
                        {
                            return byte == 0;
                        }))
        {
            identity->DiscoPrivateKey = tailgate::crypto::GeneratePrivateKey();
            identityChanged = true;
        }
        if (!requestedSettings.Hostname.empty() && identity->Hostname != host.Hostname())
        {
            identity->Hostname = host.Hostname();
            identityChanged = true;
        }
        if (identityChanged)
        {
            tailgate::linux_frontend::WriteIdentity(*identity);
        }
    }
    requestedSettings.Hostname = host.Hostname();
    tailgate::linux_frontend::WriteSettings(requestedSettings);

    int readyPipe[2]{};
    if (pipe(readyPipe) != 0)
    {
        throw std::runtime_error("failed to create daemon readiness pipe");
    }

    const pid_t pid = fork();
    if (pid < 0)
    {
        close(readyPipe[0]);
        close(readyPipe[1]);
        throw std::runtime_error("failed to fork Tailgate daemon");
    }
    if (pid > 0)
    {
        close(readyPipe[1]);
        struct sigaction action{};
        action.sa_handler = HandleStartupSignal;
        sigemptyset(&action.sa_mask);
        struct sigaction previousInterrupt{};
        struct sigaction previousTerminate{};
        sigaction(SIGINT, &action, &previousInterrupt);
        sigaction(SIGTERM, &action, &previousTerminate);
        Lifecycle::BeginStartup(pid);
        char ready = 0;
        ssize_t bytesRead = -1;
        std::string displayedAuthorizationUrl;
        tailgate::linux_frontend::FileChangeWaiter statusChanges(
            tailgate::linux_frontend::StateDirectory());
        const auto displayAuthorization = [&]()
        {
            const auto currentStatus = tailgate::linux_frontend::ReadDaemonStatus();
            if (currentStatus && !currentStatus->AuthorizationUrl.empty() &&
                currentStatus->AuthorizationUrl != displayedAuthorizationUrl)
            {
                displayedAuthorizationUrl = currentStatus->AuthorizationUrl;
                PrintAuthorizationPrompt(
                    displayedAuthorizationUrl, currentStatus->BackendState, options);
            }
        };
        displayAuthorization();
        while (!Lifecycle::StartupInterrupted() && bytesRead < 0)
        {
            std::array<pollfd, 2> readiness{
                pollfd{.fd = readyPipe[0], .events = POLLIN, .revents = 0},
                pollfd{.fd = statusChanges.Descriptor(), .events = POLLIN, .revents = 0},
            };
            const int pollResult = poll(readiness.data(), readiness.size(), -1);
            if (pollResult > 0 && (readiness[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0)
            {
                bytesRead = read(readyPipe[0], &ready, 1);
            }
            else if (pollResult < 0 && errno != EINTR)
            {
                break;
            }
            if (pollResult > 0 && (readiness[1].revents & POLLIN) != 0 &&
                statusChanges.TakeChange(tailgate::linux_frontend::DaemonStatusFileName))
            {
                displayAuthorization();
            }
        }
        Lifecycle::EndStartup();
        sigaction(SIGINT, &previousInterrupt, nullptr);
        sigaction(SIGTERM, &previousTerminate, nullptr);
        if (bytesRead != 1)
        {
            ready = 0;
        }
        close(readyPipe[0]);
        if (Lifecycle::StartupInterrupted())
        {
            (void)waitpid(pid, nullptr, 0);
            throw std::runtime_error("up interrupted; Tailgate daemon stopped");
        }
        if (ready == '1')
        {
            return tailgate::platform::UpResult{.Ready = true};
        }
        else
        {
            return tailgate::platform::UpResult{.Ready = false};
        }
    }

    close(readyPipe[0]);
    if (setsid() < 0)
    {
        _exit(1);
    }
    umask(0077);
    std::filesystem::create_directories(tailgate::linux_frontend::StateDirectory());
    const std::string logPath = tailgate::linux_frontend::StateDirectory() + "/tailgate.log";
    const int logFd = open(logPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    const int nullFd = open("/dev/null", O_RDONLY);
    if (logFd >= 0)
    {
        (void)dup2(logFd, STDOUT_FILENO);
        (void)dup2(logFd, STDERR_FILENO);
        close(logFd);
    }
    if (nullFd >= 0)
    {
        (void)dup2(nullFd, STDIN_FILENO);
        close(nullFd);
    }

    tailgate::base::SetLogSink(
        [](tailgate::base::LogLevel level, const std::string& component, const std::string& message)
        {
            const auto now = std::chrono::system_clock::now();
            const auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
            const auto milliseconds =
                std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds).count();
            std::osyncstream(std::cerr) << std::format("{:%Y-%m-%dT%H:%M:%S}.{:03}Z [{}] {}: {}\n",
                                                       seconds,
                                                       milliseconds,
                                                       tailgate::base::LogLevelName(level),
                                                       component,
                                                       message)
                                        << std::flush;
        });

    tailgate::base::Log(tailgate::base::LogLevel::Info,
                        "daemon",
                        std::format("started pid={} hostname={} state={}",
                                    getpid(),
                                    host.Hostname(),
                                    tailgate::linux_frontend::StateDirectory()));

    std::signal(SIGTERM, HandleStopSignal);
    std::signal(SIGINT, HandleStopSignal);
    std::signal(SIGHUP, HandleStopSignal);
    std::signal(SIGUSR1, HandleReloadSignal);
    std::signal(SIGPIPE, SIG_IGN);

    tailgate::linux_frontend::DaemonStatus status;
    status.ProcessId = getpid();
    status.BackendState = "Starting";
    status.Hostname = host.Hostname();
    status.OperatingSystem = host.OperatingSystem();
    status.OperatingSystemVersion = host.OperatingSystemVersion();
    status.ClientVersion = host.ClientVersion();
    tailgate::linux_frontend::WriteDaemonStatus(status);

    tailgate::control::client::RetryBackoff retryBackoff(std::chrono::seconds(1),
                                                         std::chrono::seconds(30));
    std::size_t relayAddressAttempt = 0;
    int readyFd = readyPipe[1];
    tailgate::crypto::Bytes32 machineKey = identity->MachinePrivateKey;
    tailgate::crypto::Bytes32 nodePrivateKey = identity->NodePrivateKey;
    tailgate::crypto::Bytes32 discoPrivateKey = identity->DiscoPrivateKey;
    std::string pendingAuthKey = identity->RegistrationComplete ? std::string{} : authKey;
    std::string fallbackAuthKey = identity->RegistrationComplete ? authKey : std::string{};
    std::string pendingAuthorizationUrl;
    tailgate::linux_frontend::Registration registration(
        pendingAuthKey, fallbackAuthKey, pendingAuthorizationUrl, status);
    const auto recordConnectionFailure = [&](const std::exception& error)
    {
        tailgate::linux_frontend::RestoreResolverConfiguration();
        if (status.Online)
        {
            retryBackoff.Reset();
        }
        const std::chrono::milliseconds retryDelay = retryBackoff.NextDelay();
        const auto retrySeconds =
            std::chrono::duration_cast<std::chrono::seconds>(retryDelay).count();
        status.BackendState = "Starting";
        status.Online = false;
        status.Error = error.what();
        tailgate::linux_frontend::WriteDaemonStatus(status);
        tailgate::base::Log(tailgate::base::LogLevel::Error,
                            "daemon",
                            std::format("{}; retrying in {} seconds", error.what(), retrySeconds));
        (void)Lifecycle::WaitForChange(retryDelay);
    };
    while (!Lifecycle::Stopping())
    {
        try
        {
            const auto settings = tailgate::linux_frontend::ReadSettings();
            if (const auto currentIdentity = tailgate::linux_frontend::ReadIdentity())
            {
                machineKey = currentIdentity->MachinePrivateKey;
                nodePrivateKey = currentIdentity->NodePrivateKey;
                discoPrivateKey = currentIdentity->DiscoPrivateKey;
            }
            if (settings && !settings->Hostname.empty())
            {
                host.SetHostname(settings->Hostname);
            }
            Lifecycle::ClearReload();
            tailgate::linux_frontend::RestoreResolverConfiguration();
            const std::string selectedExitNode = settings ? settings->ExitNode : options.ExitNode;
            status.ConfigurationRevision = settings ? settings->Revision : 0;
            status.BackendState = "Starting";
            status.Online = false;
            status.Error.clear();
            tailgate::linux_frontend::WriteDaemonStatus(status);
            tailgate::base::Log(
                tailgate::base::LogLevel::Info,
                "daemon",
                std::format("connecting hostname={} accept-dns={} exit-node={}",
                            host.Hostname(),
                            (settings ? settings->AcceptDns : options.AcceptDns) ? "true" : "false",
                            selectedExitNode.empty() ? "none" : selectedExitNode));
            const std::string tailgateUrl = settings ? settings->TailgateUrl : options.TailgateUrl;
            if (!tailgateUrl.empty())
            {
                tailgate::linux_frontend::RunHostedClient(
                    tailgateUrl,
                    pendingAuthKey,
                    pendingAuthorizationUrl,
                    host,
                    machineKey,
                    nodePrivateKey,
                    discoPrivateKey,
                    settings ? settings->AcceptDns : options.AcceptDns,
                    settings ? settings->ExitNode : options.ExitNode,
                    status,
                    readyFd,
                    relayAddressAttempt++,
                    registration,
                    fallbackAuthKey);
            }
            else
            {
                tailgate::linux_frontend::RunDirectConnection(
                    pendingAuthKey,
                    host,
                    machineKey,
                    nodePrivateKey,
                    settings ? settings->AcceptDns : options.AcceptDns,
                    settings ? settings->ExitNode : options.ExitNode,
                    settings ? settings->FunnelPort : 0,
                    settings ? settings->FunnelLocalPort : 0,
                    settings ? settings->ExposePort : 0,
                    status,
                    readyFd,
                    pendingAuthorizationUrl,
                    registration,
                    fallbackAuthKey);
            }
            if (Lifecycle::Reloading())
            {
                tailgate::base::Log(tailgate::base::LogLevel::Info,
                                    "daemon",
                                    "settings changed; reconnecting data plane");
            }
            retryBackoff.Reset();
        }
        catch (const std::exception& error)
        {
            recordConnectionFailure(error);
        }
    }

    tailgate::base::Log(tailgate::base::LogLevel::Info, "daemon", "shutdown requested");
    tailgate::linux_frontend::RestoreResolverConfiguration();

    if (readyFd >= 0)
    {
        close(readyFd);
    }
    tailgate::linux_frontend::RemoveResolverBackup();
    tailgate::base::Log(tailgate::base::LogLevel::Info, "daemon", "shutdown complete");
    _exit(0);
}

} // namespace

namespace tailgate::platform
{
namespace
{

class Frontend final : public IPlatformFrontend
{
public:
    Frontend()
    {
        Lifecycle::Initialize();
    }

    UpResult Up(const cli::UpOptions& options) override
    {
        return RunUp(options);
    }

    int Down() override
    {
        return RunDown();
    }

    int Logout() override
    {
        return RunLogout();
    }

    int Set(const cli::SetOptions& options) override
    {
        const auto existing = RequireRunningDaemon();
        tailgate::linux_frontend::SettingsState settings =
            tailgate::linux_frontend::ReadSettings().value_or(
                tailgate::linux_frontend::SettingsState{});
        const tailgate::linux_frontend::SettingsState previousSettings = settings;
        if (options.Hostname)
        {
            settings.Hostname = *options.Hostname;
        }
        if (options.ExitNode)
        {
            settings.ExitNode = *options.ExitNode;
        }
        if (options.TailgateUrl)
        {
            if (!options.TailgateUrl->empty() && settings.ExposePort != 0)
            {
                throw std::runtime_error(
                    "this node is running expose; stop expose before enabling --tailgate");
            }
            settings.TailgateUrl = *options.TailgateUrl;
        }
        Lifecycle::ClearStop();
        std::signal(SIGINT, HandleStopSignal);
        std::signal(SIGTERM, HandleStopSignal);
        tailgate::linux_frontend::WriteSettings(settings);
        ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
        try
        {
            (void)WaitForDaemonReload(static_cast<pid_t>(existing.ProcessId), existing.Error, true);
        }
        catch (...)
        {
            const std::exception_ptr failure = std::current_exception();
            tailgate::linux_frontend::WriteSettings(previousSettings);
            ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
            Lifecycle::ClearStop();
            try
            {
                (void)WaitForDaemonReload(static_cast<pid_t>(existing.ProcessId));
            }
            catch (const std::exception& rollbackError)
            {
                tailgate::base::Log(tailgate::base::LogLevel::Error,
                                    "settings",
                                    "failed to restore previous settings: " +
                                        std::string(rollbackError.what()));
            }
            std::rethrow_exception(failure);
        }
        return 0;
    }

    int Funnel(const cli::FunnelOptions& options) override
    {
        tailgate::linux_frontend::DaemonStatus existing = RequireRunningDaemon();
        tailgate::linux_frontend::SettingsState settings =
            tailgate::linux_frontend::ReadSettings().value_or(
                tailgate::linux_frontend::SettingsState{});
        if (options.Off)
        {
            if (settings.FunnelPort == options.Port)
            {
                settings.FunnelPort = 0;
                settings.FunnelLocalPort = 0;
                tailgate::linux_frontend::WriteSettings(settings);
                ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
                WaitForDaemonReload(static_cast<pid_t>(existing.ProcessId), existing.Error);
            }
            std::cout << "Funnel stopped.\n";
            return 0;
        }
        const tailgate::linux_frontend::SettingsState previousSettings = settings;
        settings.FunnelPort = options.Port;
        settings.FunnelLocalPort = options.LocalPort;
        tailgate::linux_frontend::WriteSettings(settings);
        ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
        try
        {
            existing = WaitForDaemonReload(static_cast<pid_t>(existing.ProcessId), existing.Error);
        }
        catch (...)
        {
            const auto failedStatus = tailgate::linux_frontend::ReadDaemonStatus();
            const std::string failedError = failedStatus ? failedStatus->Error : "";
            tailgate::linux_frontend::WriteSettings(previousSettings);
            try
            {
                ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
                (void)WaitForDaemonReload(static_cast<pid_t>(existing.ProcessId), failedError);
            }
            catch (const std::exception& rollbackError)
            {
                tailgate::base::Log(tailgate::base::LogLevel::Error,
                                    "funnel",
                                    "failed to restore previous settings: " +
                                        std::string(rollbackError.what()));
            }
            throw;
        }
        PrintFunnelAvailability(existing, options, options.Background);
        if (options.Background)
        {
            return 0;
        }
        std::signal(SIGINT, HandleStopSignal);
        std::signal(SIGTERM, HandleStopSignal);
        while (!Lifecycle::Stopping())
        {
            pause();
        }
        settings = tailgate::linux_frontend::ReadSettings().value_or(settings);
        if (settings.FunnelPort == options.Port)
        {
            settings.FunnelPort = 0;
            settings.FunnelLocalPort = 0;
            tailgate::linux_frontend::WriteSettings(settings);
            existing = RequireRunningDaemon();
            ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
        }
        return 0;
    }

    int Expose(const cli::ExposeOptions& options) override
    {
        tailgate::linux_frontend::DaemonStatus existing = RequireRunningDaemon();
        tailgate::linux_frontend::SettingsState settings =
            tailgate::linux_frontend::ReadSettings().value_or(
                tailgate::linux_frontend::SettingsState{});
        if (options.Off)
        {
            if (settings.ExposePort == options.Port)
            {
                settings.ExposePort = 0;
                settings.FunnelPort = 0;
                settings.FunnelLocalPort = 0;
                tailgate::linux_frontend::WriteSettings(settings);
                ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
                (void)WaitForDaemonReload(static_cast<pid_t>(existing.ProcessId), existing.Error);
            }
            std::cout << "Tailgate expose stopped.\n";
            return 0;
        }

        const tailgate::linux_frontend::SettingsState previousSettings = settings;
        settings.ExposePort = options.Port;
        settings.FunnelPort = options.Port;
        settings.FunnelLocalPort = ExposeLocalPort;
        tailgate::linux_frontend::WriteSettings(settings);
        ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
        try
        {
            existing = WaitForDaemonReload(static_cast<pid_t>(existing.ProcessId), existing.Error);
        }
        catch (...)
        {
            tailgate::linux_frontend::WriteSettings(previousSettings);
            ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
            throw;
        }
        const std::string url =
            std::format("https://{}.{}:{}", existing.Hostname, existing.Domain, options.Port);
        std::cout << std::format("Exposed to the internet at: {}\n\n", url);
        if (options.Background)
        {
            std::cout << "Tailgate opened and running in the background.\n";
            std::cout << std::format("To disable the proxy, run: tailgate expose --port={} off\n",
                                     options.Port);
            return 0;
        }
        std::cout << "Press Ctrl+C to exit.\n";
        std::signal(SIGINT, HandleStopSignal);
        std::signal(SIGTERM, HandleStopSignal);
        while (!Lifecycle::Stopping())
        {
            pause();
        }
        settings = tailgate::linux_frontend::ReadSettings().value_or(settings);
        if (settings.ExposePort == options.Port)
        {
            settings.ExposePort = 0;
            settings.FunnelPort = 0;
            settings.FunnelLocalPort = 0;
            tailgate::linux_frontend::WriteSettings(settings);
            existing = RequireRunningDaemon();
            ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
        }
        return 0;
    }

    tailgate::Status ReadStatus() override
    {
        std::optional<tailgate::linux_frontend::DaemonStatus> status =
            tailgate::linux_frontend::ReadDaemonStatus();
        if (!status)
        {
            return {};
        }
        if (!tailgate::linux_frontend::IsProcessRunning(status->ProcessId))
        {
            status->Online = false;
            status->BackendState = "Stopped";
            tailgate::linux_frontend::RestoreResolverConfiguration();
        }
        return *status;
    }

    PingResult PingOnce(const std::string& target,
                        int timeoutSeconds,
                        std::uint16_t sequence,
                        bool tsmp) override
    {
        (void)sequence;
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        addrinfo* addresses = nullptr;
        const int result = getaddrinfo(target.c_str(), nullptr, &hints, &addresses);
        if (result != 0)
        {
            throw std::runtime_error(
                std::format("cannot resolve {}: {}", target, gai_strerror(result)));
        }
        std::string resolved;
        for (addrinfo* current = addresses; current != nullptr; current = current->ai_next)
        {
            const auto* address = reinterpret_cast<const sockaddr_in*>(current->ai_addr);
            std::vector<char> text(INET_ADDRSTRLEN);
            if (inet_ntop(AF_INET,
                          &address->sin_addr,
                          text.data(),
                          static_cast<socklen_t>(text.size())) != nullptr)
            {
                resolved = text.data();
                break;
            }
        }
        freeaddrinfo(addresses);
        if (resolved.empty())
        {
            throw std::runtime_error("cannot resolve " + target + " to an IPv4 address");
        }
        const tailgate::Status status = ReadStatus();
        if (!status.Address.empty() && resolved == status.Address)
        {
            PingResult local;
            local.Local = true;
            local.NodeName = status.Hostname;
            local.NodeAddress = status.Address;
            return local;
        }
        return tailgate::linux_frontend::RequestDaemonPing(resolved, timeoutSeconds, tsmp);
    }
};

} // namespace

std::unique_ptr<IPlatformFrontend> CreateFrontend()
{
    namespace di = boost::di;
    auto injector = di::make_injector(di::bind<IPlatformFrontend>.to<Frontend>());
    return injector.create<std::unique_ptr<IPlatformFrontend>>();
}

} // namespace tailgate::platform
