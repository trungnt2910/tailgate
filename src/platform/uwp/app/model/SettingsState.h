#pragma once

#include <optional>
#include <vector>

#include <winrt/base.h>

#include <tailgate/crypto/Crypto.h>

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

struct UwpDevice
{
    bool operator==(const UwpDevice&) const = default;

    [[nodiscard]] winrt::hstring MagicDnsName() const;
    [[nodiscard]] bool MatchesExitNode(const winrt::hstring& nameOrAddress) const;
    [[nodiscard]] winrt::hstring ShortName() const;

    winrt::hstring Group;
    winrt::hstring Name;
    winrt::hstring Address;
    winrt::hstring Ipv6;
    winrt::hstring OperatingSystem;
    bool Online = false;
    bool ExitNodeOption = false;
};

struct ConnectionSettingsSnapshot
{
    bool operator==(const ConnectionSettingsSnapshot&) const = default;

    std::optional<winrt::hstring> TailgateServer;
    std::optional<winrt::hstring> Hostname;
    std::optional<winrt::hstring> ExitNode;
    std::optional<winrt::hstring> ExitNodeSelection;
};

class SettingsState final : public ObservableState<SettingsState>
{
public:
    SettingsState() = default;

    [[nodiscard]] winrt::hstring AccountTitle() const;
    [[nodiscard]] winrt::hstring TailgateHostPort() const;
    [[nodiscard]] winrt::hstring TailnetTitle() const;

    TAILGATE_PROPERTY(TailnetName, winrt::hstring);
    TAILGATE_PROPERTY(TailnetDisplayName, winrt::hstring);
    TAILGATE_PROPERTY(AccountName, winrt::hstring);
    TAILGATE_PROPERTY(AccountDisplayName, winrt::hstring);
    TAILGATE_PROPERTY(ProfilePicUrl, winrt::hstring);
    TAILGATE_PROPERTY(TailgateServer, winrt::hstring);
    TAILGATE_PROPERTY(Hostname, winrt::hstring);
    TAILGATE_PROPERTY(ExitNode, winrt::hstring);
    TAILGATE_PROPERTY(ExitNodeSelection, winrt::hstring);
    TAILGATE_PROPERTY(CachedProfilePictureUrl, winrt::hstring);
    TAILGATE_PROPERTY(AuthKey, winrt::hstring);
    TAILGATE_PROPERTY(SelfAddress, winrt::hstring);
    TAILGATE_PROPERTY(MachinePrivateKey, std::optional<tailgate::crypto::Bytes32>);
    TAILGATE_PROPERTY(NodePrivateKey, std::optional<tailgate::crypto::Bytes32>);
    TAILGATE_PROPERTY(Devices, std::vector<UwpDevice>);
    TAILGATE_PROPERTY(ConnectionSettings, ConnectionSettingsSnapshot);
    TAILGATE_PROPERTY(RegistrationComplete, bool);
    TAILGATE_PROPERTY(ProfileValidated, bool);
    TAILGATE_PROPERTY(HasStoredProfile, bool);
    TAILGATE_PROPERTY(Loaded, bool);
};

} // namespace tailgate::uwp
