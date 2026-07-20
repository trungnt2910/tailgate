#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace tailgate::cli
{

enum class Command
{
    Up,
    Down,
    Logout,
    Status,
    Ping,
    Set,
    Funnel,
    Expose,
    Help,
};

struct UpOptions
{
    std::string AuthKey;
    std::string QrFormat = "auto";
    std::string Hostname;
    bool AcceptDns = true;
    std::string ExitNode;
    std::string TailgateUrl;
    bool Reset = false;
    bool Qr = false;
    bool HostnameSet = false;
    bool AcceptDnsSet = false;
    bool ExitNodeSet = false;
    bool TailgateUrlSet = false;
};

struct SetOptions
{
    std::optional<std::string> Hostname;
    std::optional<std::string> ExitNode;
    std::optional<std::string> TailgateUrl;
};

struct StatusOptions
{
    bool Json = false;
    bool Active = false;
};

struct PingOptions
{
    std::string Target;
    int Count = 10;
    int TimeoutSeconds = 5;
    bool UntilDirect = true;
    bool Tsmp = false;
};

struct FunnelOptions
{
    int Port = 0;
    int LocalPort = 0;
    std::string Target;
    bool Off = false;
    bool Background = false;
};

struct ExposeOptions
{
    int Port = 0;
    std::string Action;
    bool Off = false;
    bool Background = false;
};

struct Arguments
{
    Command SelectedCommand = Command::Help;
    UpOptions Up;
    StatusOptions Status;
    PingOptions Ping;
    SetOptions Set;
    FunnelOptions Funnel;
    ExposeOptions Expose;
    std::string HelpOutput;

    [[nodiscard]] static Arguments Parse(const std::vector<std::string>& arguments);
    [[nodiscard]] static std::string HelpText();
};

class ArgumentError : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

} // namespace tailgate::cli
