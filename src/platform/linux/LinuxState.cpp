#include "LinuxState.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <mutex>
#include <stdexcept>

#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/net/dns/ResolverConfig.h>

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

std::string AcmePath()
{
    return StateDirectory() + "/acme.json";
}

std::string RelaySessionPath()
{
    return StateDirectory() + "/relay-session.json";
}

std::string LegacyHostedProfilesPath()
{
    return StateDirectory() + "/hosted-profiles.json";
}

tailgate::crypto::Bytes32 DecodeStoredKey(const nlohmann::json& json, const char* name)
{
    const std::vector<std::uint8_t> bytes = tailgate::crypto::HexToBytes(json.value(name, ""));
    if (bytes.size() != tailgate::crypto::Bytes32{}.size())
    {
        throw std::runtime_error(std::string("invalid stored key ") + name);
    }
    tailgate::crypto::Bytes32 result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
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
    result.Domain = json.value("Domain", "");
    result.Hostname = json.value("HostName", "");
    result.OperatingSystem = json.value("OS", "");
    result.OperatingSystemVersion = json.value("OSVersion", "");
    result.ClientVersion = json.value("Version", "Tailgate");
    result.AuthorizationUrl = json.value("AuthURL", "");
    result.Error = json.value("Error", "");
    result.ConfigurationRevision = json.value("ConfigurationRevision", std::uint64_t{0});
    if (json.contains("Peer") && json.at("Peer").is_array())
    {
        for (const nlohmann::json& peer : json.at("Peer"))
        {
            result.Peers.push_back(PeerStatus{.Address = peer.value("TailscaleIP", ""),
                                              .Hostname = peer.value("HostName", ""),
                                              .OperatingSystem = peer.value("OS", ""),
                                              .Relay = peer.value("Relay", ""),
                                              .Endpoint = peer.value("CurAddr", ""),
                                              .Online = peer.value("Online", false),
                                              .Active = peer.value("Active", false),
                                              .Direct = peer.value("Direct", false),
                                              .ExitNodeOption = peer.value("ExitNodeOption", false),
                                              .TxBytes = peer.value("TxBytes", std::uint64_t{0}),
                                              .RxBytes = peer.value("RxBytes", std::uint64_t{0})});
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
        {"Domain", status.Domain},
        {"Self",
         {{"HostName", status.Hostname},
          {"OS", status.OperatingSystem},
          {"OSVersion", status.OperatingSystemVersion}}},
        {"HostName", status.Hostname},
        {"OS", status.OperatingSystem},
        {"OSVersion", status.OperatingSystemVersion},
        {"AuthURL", status.AuthorizationUrl},
        {"Error", status.Error},
        {"ConfigurationRevision", status.ConfigurationRevision},
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
        tailgate::crypto::HexToBytes(json.value("MachinePrivateKey", ""));
    const std::vector<std::uint8_t> node =
        tailgate::crypto::HexToBytes(json.value("NodePrivateKey", ""));
    const std::vector<std::uint8_t> disco =
        tailgate::crypto::HexToBytes(json.value("DiscoPrivateKey", ""));
    if (machine.size() != tailgate::crypto::Bytes32{}.size() ||
        node.size() != tailgate::crypto::Bytes32{}.size())
    {
        throw std::runtime_error("Tailgate identity state contains invalid keys");
    }
    IdentityState result;
    std::copy(machine.begin(), machine.end(), result.MachinePrivateKey.begin());
    std::copy(node.begin(), node.end(), result.NodePrivateKey.begin());
    if (disco.size() == tailgate::crypto::Bytes32{}.size())
    {
        std::copy(disco.begin(), disco.end(), result.DiscoPrivateKey.begin());
    }
    result.Hostname = json.value("Hostname", "");
    result.RegistrationComplete = json.value("RegistrationComplete", true);
    return result;
}

void WriteIdentity(const IdentityState& identity)
{
    EnsureStateDirectory();
    const nlohmann::json json = {
        {"MachinePrivateKey",
         tailgate::crypto::BytesToHex(identity.MachinePrivateKey.data(),
                                      identity.MachinePrivateKey.size())},
        {"NodePrivateKey",
         tailgate::crypto::BytesToHex(identity.NodePrivateKey.data(),
                                      identity.NodePrivateKey.size())},
        {"DiscoPrivateKey",
         tailgate::crypto::BytesToHex(identity.DiscoPrivateKey.data(),
                                      identity.DiscoPrivateKey.size())},
        {"Hostname", identity.Hostname},
        {"RegistrationComplete", identity.RegistrationComplete},
    };
    WriteFile(IdentityPath(), json.dump(2) + "\n");
    std::filesystem::permissions(IdentityPath(),
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace);
}

void RemoveProfileState()
{
    const std::array<std::string, 4> paths{
        IdentityPath(), SettingsPath(), AcmePath(), RelaySessionPath()};
    for (const std::string& path : paths)
    {
        std::error_code error;
        std::filesystem::remove(path, error);
        if (error)
        {
            throw std::runtime_error("failed to remove Tailgate profile state: " + error.message());
        }
    }
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
    return SettingsState{.Hostname = json.value("Hostname", ""),
                         .ExitNode = json.value("ExitNode", ""),
                         .AcceptDns = json.value("AcceptDns", true),
                         .FunnelPort = json.value("FunnelPort", 0),
                         .FunnelLocalPort = json.value("FunnelLocalPort", 0),
                         .ExposePort = json.value("ExposePort", 0),
                         .TailgateUrl = json.value("TailgateUrl", ""),
                         .Revision = json.value("Revision", std::uint64_t{0})};
}

void WriteSettings(const SettingsState& settings)
{
    EnsureStateDirectory();
    std::uint64_t revision = settings.Revision;
    if (const std::optional<SettingsState> current = ReadSettings())
    {
        revision = std::max(revision, current->Revision + 1);
    }
    else
    {
        revision = std::max(revision, std::uint64_t{1});
    }
    WriteFile(SettingsPath(),
              nlohmann::json({
                                 {"Hostname", settings.Hostname},
                                 {"ExitNode", settings.ExitNode},
                                 {"AcceptDns", settings.AcceptDns},
                                 {"FunnelPort", settings.FunnelPort},
                                 {"FunnelLocalPort", settings.FunnelLocalPort},
                                 {"ExposePort", settings.ExposePort},
                                 {"TailgateUrl", settings.TailgateUrl},
                                 {"Revision", revision},
                             })
                      .dump(2) +
                  "\n");
}

std::optional<AcmeState> ReadAcmeState()
{
    std::ifstream stream(AcmePath());
    if (!stream)
    {
        return std::nullopt;
    }
    const nlohmann::json json = nlohmann::json::parse(stream, nullptr, false);
    if (json.is_discarded())
    {
        throw std::runtime_error("Tailgate ACME state is not valid JSON");
    }
    return AcmeState{.Domain = json.value("Domain", ""),
                     .AccountPrivateKey = json.value("AccountPrivateKey", ""),
                     .CertificatePem = json.value("CertificatePem", ""),
                     .PrivateKeyPem = json.value("PrivateKeyPem", "")};
}

void WriteAcmeState(const AcmeState& state)
{
    EnsureStateDirectory();
    WriteFile(AcmePath(),
              nlohmann::json({{"Domain", state.Domain},
                              {"AccountPrivateKey", state.AccountPrivateKey},
                              {"CertificatePem", state.CertificatePem},
                              {"PrivateKeyPem", state.PrivateKeyPem}})
                      .dump(2) +
                  "\n");
    std::filesystem::permissions(AcmePath(),
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace);
}

std::optional<RelaySessionState> ReadRelaySession()
{
    std::ifstream stream(RelaySessionPath());
    if (!stream)
    {
        return std::nullopt;
    }
    const nlohmann::json json = nlohmann::json::parse(stream, nullptr, false);
    if (json.is_discarded())
    {
        throw std::runtime_error("Tailgate relay session is not valid JSON");
    }
    return RelaySessionState{.ServerUrl = json.value("ServerUrl", ""),
                             .Tailnet = json.value("Tailnet", ""),
                             .RelayPublicKey = json.contains("RelayPublicKey")
                                                   ? DecodeStoredKey(json, "RelayPublicKey")
                                                   : tailgate::crypto::Bytes32{}};
}

void WriteRelaySession(const RelaySessionState& state)
{
    EnsureStateDirectory();
    WriteFile(RelaySessionPath(),
              nlohmann::json({{"ServerUrl", state.ServerUrl},
                              {"Tailnet", state.Tailnet},
                              {"RelayPublicKey",
                               tailgate::crypto::BytesToHex(state.RelayPublicKey.data(),
                                                            state.RelayPublicKey.size())}})
                      .dump(2) +
                  "\n");
    std::filesystem::permissions(RelaySessionPath(),
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace);
}

void RemoveRelaySession()
{
    std::error_code error;
    std::filesystem::remove(RelaySessionPath(), error);
    if (error)
    {
        throw std::runtime_error("failed to remove Tailgate relay session: " + error.message());
    }
}

void RemoveLegacyHostedProfiles()
{
    std::error_code error;
    std::filesystem::remove(LegacyHostedProfilesPath(), error);
    if (error)
    {
        throw std::runtime_error("failed to remove legacy hosted profile state: " +
                                 error.message());
    }
}

bool IsProcessRunning(pid_t pid)
{
    if (pid <= 0 || (kill(pid, 0) != 0 && errno != EPERM))
    {
        return false;
    }
    std::ifstream comm(std::format("/proc/{}/comm", pid));
    std::string name;
    std::getline(comm, name);
    return name == "tailgate";
}

void SaveResolverConfiguration()
{
    // Resolver ownership is represented by a managed section, not a whole-file backup.
}

void RestoreResolverConfiguration()
{
    const std::string current = ReadFile("/etc/resolv.conf");
    const std::string restored = tailgate::net::dns::RemoveResolverSection(current);
    if (restored != current)
    {
        WriteFile("/etc/resolv.conf", restored);
    }
}

void RemoveResolverBackup()
{
    std::error_code ignored;
    std::filesystem::remove(ResolverBackupPath(), ignored);
}

} // namespace tailgate::linux_frontend
