#include "tailgate/Application.h"

#include <algorithm>
#include <chrono>
#include <format>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "tailgate/cli/Arguments.h"

namespace tailgate
{
namespace
{

std::string PeerDetail(const PeerStatus& peer)
{
    if (!peer.Active)
    {
        if (peer.ExitNodeOption)
        {
            return std::format("idle; offers exit node{}", peer.Online ? "" : "; offline");
        }
        return peer.Online ? (peer.TxBytes || peer.RxBytes ? "idle" : "-") : "offline";
    }

    std::string result = "active; ";
    if (peer.ExitNodeOption)
    {
        result += "offers exit node; ";
    }
    result += peer.Direct ? std::format("direct {}", peer.Endpoint)
                          : std::format("relay \"{}\"", peer.Relay);
    if (peer.TxBytes != 0 || peer.RxBytes != 0)
    {
        result += std::format(", tx {} rx {}", peer.TxBytes, peer.RxBytes);
    }
    return result;
}

void PrintStatusJson(const Status& status, bool activeOnly)
{
    nlohmann::json peers = nlohmann::json::array();
    for (const PeerStatus& peer : status.Peers)
    {
        if (activeOnly && !peer.Active)
        {
            continue;
        }
        peers.push_back({
            {"TailscaleIP", peer.Address},
            {"HostName", peer.Hostname},
            {"OS", peer.OperatingSystem},
            {"Online", peer.Online},
            {"Active", peer.Active},
            {"CurAddr", peer.Endpoint},
            {"Relay", peer.Relay},
            {"ExitNodeOption", peer.ExitNodeOption},
            {"TxBytes", peer.TxBytes},
            {"RxBytes", peer.RxBytes},
        });
    }
    std::cout << nlohmann::json(
                     {
                         {"Version", status.ClientVersion},
                         {"BackendState", status.BackendState},
                         {"Online", status.Online},
                         {"TailscaleIPs",
                          status.Address.empty() ? nlohmann::json::array()
                                                 : nlohmann::json::array({status.Address})},
                         {"Domain", status.Domain},
                         {"Self",
                          {{"HostName", status.Hostname},
                           {"OS", status.OperatingSystem},
                           {"OSVersion", status.OperatingSystemVersion}}},
                         {"AuthURL", status.AuthorizationUrl},
                         {"Peer", std::move(peers)},
                         {"Error", status.Error},
                     })
                     .dump(2)
              << "\n";
}

void PrintStatus(const Status& status, const cli::StatusOptions& options)
{
    if (options.Json)
    {
        PrintStatusJson(status, options.Active);
        return;
    }
    if (!status.Online)
    {
        std::cout << std::format("Tailgate is {}.\n",
                                 status.BackendState == "Stopped" ? "stopped" : "starting");
        if (!status.AuthorizationUrl.empty())
        {
            std::cout << std::format("{}{}\n",
                                     status.BackendState == "NeedsMachineAuth" ? "\nApprove at: "
                                                                               : "\nLog in at: ",
                                     status.AuthorizationUrl);
        }
        if (!status.Error.empty())
        {
            std::cout << std::format("# Health check:\n#     - {}\n", status.Error);
        }
        return;
    }

    std::size_t addressWidth = status.Address.size();
    std::size_t hostWidth = status.Hostname.size();
    std::size_t osWidth = status.OperatingSystem.size();
    for (const PeerStatus& peer : status.Peers)
    {
        addressWidth = std::max(addressWidth, peer.Address.size());
        hostWidth = std::max(hostWidth, peer.Hostname.size());
        osWidth = std::max(osWidth, peer.OperatingSystem.size());
    }
    const auto row = [&](const std::string& address,
                         const std::string& host,
                         const std::string& os,
                         const std::string& detail)
    {
        std::cout << std::format("{:<{}}{:<{}}{:<3}{:<{}}{}\n",
                                 address,
                                 addressWidth + 2,
                                 host,
                                 hostWidth + 2,
                                 "-",
                                 os,
                                 osWidth + 2,
                                 detail);
    };
    row(status.Address, status.Hostname, status.OperatingSystem, "-");
    for (const PeerStatus& peer : status.Peers)
    {
        if (!options.Active || peer.Active)
        {
            row(peer.Address, peer.Hostname, peer.OperatingSystem, PeerDetail(peer));
        }
    }
}

int RunPing(platform::IPlatformFrontend& frontend, const cli::PingOptions& options)
{
    bool receivedAny = false;
    for (int attempt = 1; options.Count == 0 || attempt <= options.Count; ++attempt)
    {
        const platform::PingResult result = frontend.PingOnce(options.Target,
                                                              options.TimeoutSeconds,
                                                              static_cast<std::uint16_t>(attempt),
                                                              options.Tsmp);
        if (result.Local)
        {
            std::cout << std::format("{} is local Tailscale IP\n", result.NodeAddress);
            return 0;
        }
        if (result.Responded)
        {
            receivedAny = true;
            const std::string via =
                options.Tsmp ? "TSMP"
                             : (result.Endpoint.empty() ? std::format("DERP({})", result.Relay)
                                                        : result.Endpoint);
            const std::string peerApiPort =
                result.PeerApiPort == 0 ? "" : std::format(", {}", result.PeerApiPort);
            std::cout << std::format("pong from {} ({}{}) via {} in {}ms\n",
                                     result.NodeName,
                                     result.NodeAddress,
                                     peerApiPort,
                                     via,
                                     result.LatencyMilliseconds);
            if (options.Tsmp || (options.UntilDirect && !result.Endpoint.empty()))
            {
                return 0;
            }
        }
        else
        {
            std::cout << std::format("timeout waiting for pong from {}\n", options.Target);
        }
        if (options.Count == 0 || attempt < options.Count)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    if (!receivedAny)
    {
        throw std::runtime_error("no reply");
    }
    if (options.UntilDirect)
    {
        throw std::runtime_error("direct connection not established");
    }
    return 0;
}

} // namespace

int RunApplication(int argc, char** argv, platform::IPlatformFrontend& frontend)
{
    try
    {
        std::vector<std::string> rawArguments;
        for (int index = 1; index < argc; ++index)
        {
            rawArguments.emplace_back(argv[index]);
        }
        if (rawArguments.empty())
        {
            std::cout << cli::Arguments::HelpText();
            return 0;
        }

        const cli::Arguments arguments = cli::Arguments::Parse(rawArguments);
        switch (arguments.SelectedCommand)
        {
        case cli::Command::Up:
        {
            const platform::UpResult result = frontend.Up(arguments.Up);
            if (!result.Ready)
            {
                std::cout << "Tailgate is starting in the background; run 'tailgate status'.\n";
            }
            return 0;
        }
        case cli::Command::Down:
            return frontend.Down();
        case cli::Command::Logout:
            return frontend.Logout();
        case cli::Command::Status:
        {
            const Status status = frontend.ReadStatus();
            PrintStatus(status, arguments.Status);
            return status.Online ? 0 : 1;
        }
        case cli::Command::Ping:
            return RunPing(frontend, arguments.Ping);
        case cli::Command::Set:
            return frontend.Set(arguments.Set);
        case cli::Command::Funnel:
            return frontend.Funnel(arguments.Funnel);
        case cli::Command::Expose:
            return frontend.Expose(arguments.Expose);
        case cli::Command::Help:
            std::cout << (arguments.HelpOutput.empty() ? cli::Arguments::HelpText()
                                                       : arguments.HelpOutput);
            return 0;
        }
    }
    catch (const cli::ArgumentError& error)
    {
        std::cerr << error.what() << "\n";
        return 2;
    }
    catch (const std::exception& error)
    {
        std::cerr << std::format("tailgate: {}\n", error.what());
        return 1;
    }
    return 0;
}

} // namespace tailgate
