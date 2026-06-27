#include "LinuxState.h"

#include "tailgate/protocol/Crypto.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <pwd.h>
#include <stdexcept>

#include <sys/stat.h>
#include <unistd.h>

namespace tailgate::linux_frontend
{
namespace
{

std::string StatePath()
{
    return StateDirectory() + "/state.json";
}

std::string StateTemporaryPath()
{
    return StateDirectory() + "/state.json.tmp";
}

std::string ResolverBackupPath()
{
    return StateDirectory() + "/resolv.conf.backup";
}

std::string IdentityPath()
{
    return StateDirectory() + "/identity.json";
}

std::string SettingsPath()
{
    return StateDirectory() + "/settings.json";
}

std::string ReadFile(const std::string& path)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream)
    {
        throw std::runtime_error("failed to read " + path);
    }
    return {
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>(),
    };
}

void WriteFile(const std::string& path, const std::string& contents)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream)
    {
        throw std::runtime_error("failed to write " + path);
    }
    stream << contents;
    if (!stream)
    {
        throw std::runtime_error("failed to flush " + path);
    }
}

void EnsureStateDirectory()
{
    std::filesystem::create_directories(StateDirectory());
    std::filesystem::permissions(StateDirectory(),
                                 std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
}

} // namespace

const std::string& StateDirectory()
{
    static const std::string path = []()
    {
        if (const char* home = std::getenv("HOME"); home != nullptr && home[0] != '\0')
        {
            return std::string(home) + "/.tailgate";
        }
        const passwd* user = getpwuid(getuid());
        if (user == nullptr || user->pw_dir == nullptr || user->pw_dir[0] == '\0')
        {
            throw std::runtime_error("failed to identify the Tailgate state directory");
        }
        return std::string(user->pw_dir) + "/.tailgate";
    }();
    return path;
}

std::optional<DaemonStatus> ReadDaemonStatus()
{
    std::ifstream stream(StatePath());
    if (!stream)
    {
        return std::nullopt;
    }
    const nlohmann::json json = nlohmann::json::parse(stream, nullptr, false);
    if (json.is_discarded())
    {
        return std::nullopt;
    }

    DaemonStatus result;
    result.ProcessId = json.value("pid", 0);
    result.BackendState = json.value("BackendState", "Stopped");
    result.Online = json.value("Online", false);
    result.Address = json.value("TailscaleIPs", std::vector<std::string>{}).empty()
                         ? ""
                         : json.at("TailscaleIPs").at(0).get<std::string>();
    result.Hostname = json.value("HostName", "");
    result.OperatingSystem = json.value("OS", "");
    result.OperatingSystemVersion = json.value("OSVersion", "");
    result.ClientVersion = json.value("Version", "Tailgate");
    result.Error = json.value("Error", "");
    if (json.contains("Peer") && json.at("Peer").is_array())
    {
        for (const nlohmann::json& peer : json.at("Peer"))
        {
            result.Peers.push_back({
                peer.value("TailscaleIP", ""),
                peer.value("HostName", ""),
                peer.value("OS", ""),
                peer.value("Relay", ""),
                peer.value("CurAddr", ""),
                peer.value("Online", false),
                peer.value("Active", false),
                peer.value("Direct", false),
                peer.value("ExitNodeOption", false),
                peer.value("TxBytes", std::uint64_t{0}),
                peer.value("RxBytes", std::uint64_t{0}),
            });
        }
    }
    return result;
}

void WriteDaemonStatus(const DaemonStatus& status)
{
    EnsureStateDirectory();
    nlohmann::json peers = nlohmann::json::array();
    for (const PeerStatus& peer : status.Peers)
    {
        peers.push_back({
            {"TailscaleIP", peer.Address},
            {"HostName", peer.Hostname},
            {"OS", peer.OperatingSystem},
            {"Relay", peer.Relay},
            {"CurAddr", peer.Endpoint},
            {"Online", peer.Online},
            {"Active", peer.Active},
            {"Direct", peer.Direct},
            {"ExitNodeOption", peer.ExitNodeOption},
            {"TxBytes", peer.TxBytes},
            {"RxBytes", peer.RxBytes},
        });
    }
    const nlohmann::json json = {
        {"Version", status.ClientVersion},
        {"TUN", true},
        {"BackendState", status.BackendState},
        {"Online", status.Online},
        {"TailscaleIPs",
         status.Address.empty() ? nlohmann::json::array()
                                : nlohmann::json::array({status.Address})},
        {"Self",
         {{"HostName", status.Hostname},
          {"OS", status.OperatingSystem},
          {"OSVersion", status.OperatingSystemVersion}}},
        {"HostName", status.Hostname},
        {"OS", status.OperatingSystem},
        {"OSVersion", status.OperatingSystemVersion},
        {"Error", status.Error},
        {"Peer", std::move(peers)},
        {"pid", status.ProcessId},
    };
    WriteFile(StateTemporaryPath(), json.dump(2) + "\n");
    std::filesystem::rename(StateTemporaryPath(), StatePath());
}

void RemoveDaemonStatus()
{
    std::error_code ignored;
    std::filesystem::remove(StatePath(), ignored);
}

std::optional<IdentityState> ReadIdentity()
{
    std::ifstream stream(IdentityPath());
    if (!stream)
    {
        return std::nullopt;
    }
    const nlohmann::json json = nlohmann::json::parse(stream, nullptr, false);
    if (json.is_discarded())
    {
        throw std::runtime_error("Tailgate identity state is not valid JSON");
    }
    const std::vector<std::uint8_t> machine =
        protocol::HexToBytes(json.value("MachinePrivateKey", ""));
    const std::vector<std::uint8_t> node = protocol::HexToBytes(json.value("NodePrivateKey", ""));
    if (machine.size() != protocol::Bytes32{}.size() || node.size() != protocol::Bytes32{}.size())
    {
        throw std::runtime_error("Tailgate identity state contains invalid keys");
    }
    IdentityState result;
    std::copy(machine.begin(), machine.end(), result.MachinePrivateKey.begin());
    std::copy(node.begin(), node.end(), result.NodePrivateKey.begin());
    result.Hostname = json.value("Hostname", "");
    return result;
}

void WriteIdentity(const IdentityState& identity)
{
    EnsureStateDirectory();
    const nlohmann::json json = {
        {"MachinePrivateKey",
         protocol::BytesToHex(identity.MachinePrivateKey.data(),
                              identity.MachinePrivateKey.size())},
        {"NodePrivateKey",
         protocol::BytesToHex(identity.NodePrivateKey.data(), identity.NodePrivateKey.size())},
        {"Hostname", identity.Hostname},
    };
    WriteFile(IdentityPath(), json.dump(2) + "\n");
    std::filesystem::permissions(IdentityPath(),
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace);
}

std::optional<SettingsState> ReadSettings()
{
    std::ifstream stream(SettingsPath());
    if (!stream)
    {
        return std::nullopt;
    }
    const nlohmann::json json = nlohmann::json::parse(stream, nullptr, false);
    if (json.is_discarded())
    {
        throw std::runtime_error("Tailgate settings state is not valid JSON");
    }
    return SettingsState{
        json.value("Hostname", ""),
        json.value("ExitNode", ""),
        json.value("AcceptDns", true),
    };
}

void WriteSettings(const SettingsState& settings)
{
    EnsureStateDirectory();
    WriteFile(SettingsPath(),
              nlohmann::json({
                                 {"Hostname", settings.Hostname},
                                 {"ExitNode", settings.ExitNode},
                                 {"AcceptDns", settings.AcceptDns},
                             })
                      .dump(2) +
                  "\n");
}

bool IsProcessRunning(pid_t pid)
{
    if (pid <= 0 || (kill(pid, 0) != 0 && errno != EPERM))
    {
        return false;
    }
    std::ifstream comm("/proc/" + std::to_string(pid) + "/comm");
    std::string name;
    std::getline(comm, name);
    return name == "tailgate";
}

void SaveResolverConfiguration()
{
    EnsureStateDirectory();
    if (!std::filesystem::exists(ResolverBackupPath()))
    {
        WriteFile(ResolverBackupPath(), ReadFile("/etc/resolv.conf"));
    }
}

void RestoreResolverConfiguration()
{
    if (!std::filesystem::exists(ResolverBackupPath()))
    {
        return;
    }
    WriteFile("/etc/resolv.conf", ReadFile(ResolverBackupPath()));
}

void RemoveResolverBackup()
{
    std::error_code ignored;
    std::filesystem::remove(ResolverBackupPath(), ignored);
}

} // namespace tailgate::linux_frontend
