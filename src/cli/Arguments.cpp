#include <tailgate/cli/Arguments.h>

#include <algorithm>
#include <format>
#include <memory>
#include <string>
#include <string_view>

#include <CLI/CLI.hpp>

namespace tailgate::cli
{
namespace
{

class TailgateHelpFormatter final : public CLI::FormatterBase
{
public:
    std::string make_help(const CLI::App* app, std::string, CLI::AppFormatMode) const override
    {
        std::string output;
        const std::string description = app->get_description();
        const std::size_t detailsStart = description.find("\n\n");
        output += std::format(
            "{}\n\nUSAGE\n  {}\n", description.substr(0, detailsStart), app->get_usage());
        if (detailsStart != std::string::npos)
        {
            output += std::format("\n{}\n", description.substr(detailsStart + 2));
        }

        const std::vector<const CLI::App*> subcommands = app->get_subcommands({});
        if (!subcommands.empty())
        {
            std::size_t width = 0;
            for (const CLI::App* command : subcommands)
            {
                width = std::max(width, command->get_name().size());
            }
            output += "\nSUBCOMMANDS\n";
            for (const CLI::App* command : subcommands)
            {
                const std::string commandDescription = command->get_description();
                output += std::format("  {:<{}}{}\n",
                                      command->get_name(),
                                      width + 4,
                                      commandDescription.substr(0, commandDescription.find('\n')));
            }
        }

        const std::vector<const CLI::Option*> options = app->get_options(
            [app](const CLI::Option* option)
            {
                return option != app->get_help_ptr() && !option->get_positional();
            });
        if (!options.empty())
        {
            output += "\nFLAGS\n";
            for (const CLI::Option* option : options)
            {
                std::string name = option->get_name(false, true, true);
                const std::string typeName = option->get_type_name();
                if (!typeName.empty() && typeName != "BOOLEAN")
                {
                    name += std::format(" {}", typeName);
                }
                output += std::format("  {}\n      {}", name, option->get_description());
                if (!option->get_default_str().empty())
                {
                    output += std::format(" (default {})", option->get_default_str());
                }
                output += '\n';
            }
        }
        return output;
    }
};

int ParseTcpUrlPort(const std::string& value)
{
    constexpr std::string_view prefix = "tcp://localhost:";
    if (value.rfind(prefix, 0) != 0)
    {
        throw CLI::ValidationError("target must be tcp://localhost:<port>");
    }
    const std::string portText = value.substr(prefix.size());
    std::size_t consumed = 0;
    const int port = std::stoi(portText, &consumed);
    if (consumed != portText.size() || port <= 0 || port > 65535)
    {
        throw CLI::ValidationError("target port must be between 1 and 65535");
    }
    return port;
}

std::string ValidateTailgateUrl(std::string& value)
{
    if (value.empty() || value.rfind("https://", 0) == 0)
    {
        return {};
    }
    if (value.find("://") != std::string::npos)
    {
        return "tailgate URL must use HTTPS";
    }
    return {};
}

void NormalizeTailgateUrl(std::string& value)
{
    if (!value.empty() && value.rfind("https://", 0) != 0)
    {
        value = std::format("https://{}", value);
    }
}

void Configure(CLI::App& app, Arguments& result)
{
    app.name("tailgate");
    app.description("The easiest, most secure way to use WireGuard.\n\n"
                    "For help on subcommands, add --help after: \"tailgate status --help\".\n\n"
                    "This CLI is still under active development. Commands and flags will\n"
                    "change in the future.");
    app.usage("tailgate [flags] <subcommand> [command flags]");
    app.formatter(std::make_shared<TailgateHelpFormatter>());
    app.require_subcommand(1);

    CLI::App* up = app.add_subcommand(
        "up",
        "Connect to Tailscale, logging in if needed\n\n"
        "\"tailgate up\" connects this machine to the tailnet, triggering authentication if "
        "necessary.\n\n"
        "With no flags, \"tailgate up\" brings the network online without changing any settings. "
        "It is the opposite of \"tailgate down\".\n\n"
        "If flags are specified, they must be the complete set of desired settings unless "
        "--reset is also used.");
    up->usage("tailgate up [flags]");
    up->add_option("--auth-key",
                   result.Up.AuthKey,
                   "node authorization key; file:PATH reads the key from a file");
    up->add_flag("--qr", result.Up.Qr, "show QR code for login URLs");
    up->add_option("--qr-format", result.Up.QrFormat, "QR code formatting")
        ->check(CLI::IsMember({"auto", "ascii", "large", "small"}));
    CLI::Option* hostname = up->add_option(
        "--hostname", result.Up.Hostname, "Hostname to use instead of the OS hostname");
    CLI::Option* acceptDns = up->add_flag("--accept-dns",
                                          result.Up.AcceptDns,
                                          "accept DNS configuration from the admin panel")
                                 ->capture_default_str();
    CLI::Option* exitNode =
        up->add_option("--exit-node",
                       result.Up.ExitNode,
                       "Tailscale exit node (IP or base name) for internet traffic, or empty to "
                       "disable")
            ->type_name("NAME|IP");
    CLI::Option* tailgate =
        up->add_option("--tailgate", result.Up.TailgateUrl, "Tailgate expose server URL")
            ->check(CLI::Validator(ValidateTailgateUrl, "HTTPS URL"));
    up->add_flag("--reset", result.Up.Reset, "Reset unspecified settings to their defaults");
    up->callback(
        [&result, hostname, acceptDns, exitNode, tailgate]()
        {
            result.Up.HostnameSet = hostname->count() != 0;
            result.Up.AcceptDnsSet = acceptDns->count() != 0;
            result.Up.ExitNodeSet = exitNode->count() != 0;
            result.Up.TailgateUrlSet = tailgate->count() != 0;
            result.SelectedCommand = Command::Up;
        });

    CLI::App* down = app.add_subcommand("down", "Disconnect from Tailscale");
    down->usage("tailgate down");
    down->callback(
        [&result]()
        {
            result.SelectedCommand = Command::Down;
        });

    CLI::App* logout = app.add_subcommand("logout", "Disconnect and expire the current node key");
    logout->callback(
        [&result]()
        {
            result.SelectedCommand = Command::Logout;
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
    ping->add_flag("--tsmp",
                   result.Ping.Tsmp,
                   "do a TSMP-level ping (through WireGuard, but not either host OS stack)");
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
    set->add_option("--tailgate", result.Set.TailgateUrl, "Tailgate expose server URL")
        ->check(CLI::Validator(ValidateTailgateUrl, "HTTPS URL"));
    set->require_option(1, 3);
    set->callback(
        [&result]()
        {
            result.SelectedCommand = Command::Set;
        });

    CLI::App* funnel = app.add_subcommand("funnel", "Expose a local TCP service with Funnel");
    funnel
        ->add_option("--https,--tls-terminated-tcp",
                     result.Funnel.Port,
                     "HTTPS Funnel port that terminates TLS")
        ->required()
        ->check(CLI::IsMember({"443", "8443", "10000"}));
    funnel->add_flag("--bg", result.Funnel.Background, "Run in the background");
    funnel->add_option("target", result.Funnel.Target, "tcp://localhost:<local-port> or off");
    funnel->callback(
        [&result]()
        {
            result.SelectedCommand = Command::Funnel;
            if (result.Funnel.Target == "off")
            {
                result.Funnel.Off = true;
                return;
            }
            if (result.Funnel.Target.empty())
            {
                throw CLI::ValidationError("funnel requires tcp://localhost:<local-port> or off");
            }
            result.Funnel.LocalPort = ParseTcpUrlPort(result.Funnel.Target);
        });

    CLI::App* expose = app.add_subcommand("expose", "Host remote Tailgate profiles with Funnel");
    expose->add_option("--port", result.Expose.Port, "Funnel HTTPS port")
        ->required()
        ->check(CLI::IsMember({"443", "8443", "10000"}));
    expose->add_flag("--bg", result.Expose.Background, "Run in the background");
    expose->add_option("action", result.Expose.Action, "off")->check(CLI::IsMember({"off"}));
    expose->callback(
        [&result]()
        {
            result.SelectedCommand = Command::Expose;
            result.Expose.Off = result.Expose.Action == "off";
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
        if (argument == "--exit-node=" || argument == "--tailgate=")
        {
            storage.emplace_back(argument.substr(0, argument.size() - 1));
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
        if (result.SelectedCommand == Command::Up)
        {
            NormalizeTailgateUrl(result.Up.TailgateUrl);
        }
        else if (result.SelectedCommand == Command::Set && result.Set.TailgateUrl)
        {
            NormalizeTailgateUrl(*result.Set.TailgateUrl);
        }
    }
    catch (const CLI::ParseError& error)
    {
        if (error.get_exit_code() == 0)
        {
            result.SelectedCommand = Command::Help;
            const std::vector<CLI::App*> parsed = app.get_subcommands();
            result.HelpOutput = parsed.empty() ? app.help() : parsed.back()->help();
            return result;
        }
        throw ArgumentError(std::format("{}\n{}", app.help(), error.what()));
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
