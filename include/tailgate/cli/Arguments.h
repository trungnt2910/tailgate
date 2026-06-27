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
    Status,
    Ping,
    Set,
    Help,
};

struct UpOptions
{
    std::string AuthKey;
    std::string Hostname;
    bool AcceptDns = true;
    std::string ExitNode;
};

struct SetOptions
{
    std::optional<std::string> Hostname;
    std::optional<std::string> ExitNode;
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
};

struct Arguments
{
    Command SelectedCommand = Command::Help;
    UpOptions Up;
    StatusOptions Status;
    PingOptions Ping;
    SetOptions Set;

    [[nodiscard]] static Arguments Parse(const std::vector<std::string>& arguments);
    [[nodiscard]] static std::string HelpText();
};

class ArgumentError : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

} // namespace tailgate::cli
