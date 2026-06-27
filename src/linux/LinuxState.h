#pragma once

#include <optional>
#include <string>
#include <vector>

#include "tailgate/Status.h"
#include "tailgate/protocol/Crypto.h"

#include <sys/types.h>

namespace tailgate::linux_frontend
{

using PeerStatus = tailgate::PeerStatus;
using DaemonStatus = tailgate::Status;

struct IdentityState
{
    protocol::Bytes32 MachinePrivateKey{};
    protocol::Bytes32 NodePrivateKey{};
    std::string Hostname;
};

struct SettingsState
{
    std::string Hostname;
    std::string ExitNode;
    bool AcceptDns = true;
};

[[nodiscard]] const std::string& StateDirectory();
[[nodiscard]] std::optional<DaemonStatus> ReadDaemonStatus();
void WriteDaemonStatus(const DaemonStatus& status);
void RemoveDaemonStatus();
[[nodiscard]] std::optional<IdentityState> ReadIdentity();
void WriteIdentity(const IdentityState& identity);
[[nodiscard]] std::optional<SettingsState> ReadSettings();
void WriteSettings(const SettingsState& settings);
[[nodiscard]] bool IsProcessRunning(pid_t pid);

void SaveResolverConfiguration();
void RestoreResolverConfiguration();
void RemoveResolverBackup();

} // namespace tailgate::linux_frontend
