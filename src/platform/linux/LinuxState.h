#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <sys/types.h>

#include <tailgate/Status.h>
#include <tailgate/crypto/Crypto.h>

namespace tailgate::linux_frontend
{

using PeerStatus = tailgate::PeerStatus;
using DaemonStatus = tailgate::Status;

struct IdentityState
{
    tailgate::crypto::Bytes32 MachinePrivateKey{};
    tailgate::crypto::Bytes32 NodePrivateKey{};
    tailgate::crypto::Bytes32 DiscoPrivateKey{};
    std::string Hostname;
    bool RegistrationComplete = false;
};

struct SettingsState
{
    std::string Hostname;
    std::string ExitNode;
    bool AcceptDns = true;
    int FunnelPort = 0;
    int FunnelLocalPort = 0;
    int ExposePort = 0;
    std::string TailgateUrl;
    std::uint64_t Revision = 0;
};

struct AcmeState
{
    std::string Domain;
    std::string AccountPrivateKey;
    std::string CertificatePem;
    std::string PrivateKeyPem;
};

struct RelaySessionState
{
    std::string ServerUrl;
    std::string Tailnet;
    tailgate::crypto::Bytes32 RelayPublicKey{};
};

[[nodiscard]] const std::string& StateDirectory();
[[nodiscard]] std::optional<DaemonStatus> ReadDaemonStatus();
void WriteDaemonStatus(const DaemonStatus& status);
void RemoveDaemonStatus();
[[nodiscard]] std::optional<IdentityState> ReadIdentity();
void WriteIdentity(const IdentityState& identity);
void RemoveProfileState();
[[nodiscard]] std::optional<SettingsState> ReadSettings();
void WriteSettings(const SettingsState& settings);
[[nodiscard]] std::optional<AcmeState> ReadAcmeState();
void WriteAcmeState(const AcmeState& state);
[[nodiscard]] std::optional<RelaySessionState> ReadRelaySession();
void WriteRelaySession(const RelaySessionState& state);
void RemoveRelaySession();
void RemoveLegacyHostedProfiles();
[[nodiscard]] bool IsProcessRunning(pid_t pid);

void SaveResolverConfiguration();
void RestoreResolverConfiguration();
void RemoveResolverBackup();

} // namespace tailgate::linux_frontend
