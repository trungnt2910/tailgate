#include "tailgate/cli/Arguments.h"

#include <CLI/CLI.hpp>

#include <sstream>

namespace tailgate::cli
{
namespace
{

void Configure(CLI::App& app, Arguments& result)
{
    app.name("tailgate");
    app.description("Connect this host to a Tailscale network without tailscaled");
    app.require_subcommand(1);

    CLI::App* up = app.add_subcommand("up", "Connect to the tailnet");
    up->add_option("--auth-key", result.Up.AuthKey, "Node authorization key (or file:path)");
    up->add_option("--hostname", result.Up.Hostname, "Hostname to use instead of the OS hostname");
    up->add_option("--accept-dns", result.Up.AcceptDns, "Accept DNS configuration")
        ->capture_default_str();
    up->add_option("--exit-node", result.Up.ExitNode, "Exit node name or Tailscale IP");
    up->callback(
        [&result]()
        {
            result.SelectedCommand = Command::Up;
        });

    CLI::App* down = app.add_subcommand("down", "Disconnect from the tailnet");
    down->callback(
        [&result]()
        {
            result.SelectedCommand = Command::Down;
        });

    CLI::App* status = app.add_subcommand("status", "Show tailnet status");
    status->add_flag("--json", result.Status.Json, "Output JSON");
    status->add_flag("--active", result.Status.Active, "Show only active peers");
    status->callback(
        [&result]()
        {
            result.SelectedCommand = Command::Status;
        });

    CLI::App* ping = app.add_subcommand("ping", "Ping a peer and show the path used");
    ping->add_option("target", result.Ping.Target, "Hostname or Tailscale IP")->required();
    ping->add_option("-c", result.Ping.Count, "Maximum number of pings (0 for unlimited)")
        ->check(CLI::NonNegativeNumber);
    ping->add_option("--timeout", result.Ping.TimeoutSeconds, "Timeout in seconds")
        ->check(CLI::PositiveNumber);
    ping->add_flag(
            "--until-direct", result.Ping.UntilDirect, "Stop once a direct path is established")
        ->capture_default_str();
    ping->callback(
        [&result]()
        {
            result.SelectedCommand = Command::Ping;
        });

    CLI::App* set = app.add_subcommand("set", "Change Tailgate preferences");
    set->add_option(
        "--hostname", result.Set.Hostname, "Hostname to use instead of the OS hostname");
    set->add_option(
        "--exit-node", result.Set.ExitNode, "Exit node name or Tailscale IP (empty to disable)");
    set->require_option(1, 2);
    set->callback(
        [&result]()
        {
            result.SelectedCommand = Command::Set;
        });
}

} // namespace

Arguments Arguments::Parse(const std::vector<std::string>& arguments)
{
    Arguments result;
    CLI::App app;
    Configure(app, result);

    std::vector<std::string> storage{"tailgate"};
    for (const std::string& argument : arguments)
    {
        if (argument == "--exit-node=")
        {
            storage.emplace_back("--exit-node");
            storage.emplace_back("");
        }
        else
        {
            storage.push_back(argument);
        }
    }
    std::vector<char*> argv;
    argv.reserve(storage.size());
    for (std::string& argument : storage)
    {
        argv.push_back(argument.data());
    }
    try
    {
        app.parse(static_cast<int>(argv.size()), argv.data());
    }
    catch (const CLI::ParseError& error)
    {
        if (error.get_exit_code() == 0)
        {
            result.SelectedCommand = Command::Help;
            return result;
        }
        throw ArgumentError(app.help() + "\n" + error.what());
    }
    return result;
}

std::string Arguments::HelpText()
{
    Arguments result;
    CLI::App app;
    Configure(app, result);
    return app.help();
}

} // namespace tailgate::cli
