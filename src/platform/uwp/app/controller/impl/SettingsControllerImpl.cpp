#include "app/controller/impl/SettingsControllerImpl.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.UI.Core.h>

namespace tailgate::uwp
{

namespace
{

namespace json = winrt::Windows::Data::Json;
namespace storage = winrt::Windows::Storage;

constexpr wchar_t StateFileName[] = L"tailgate-state.json";
constexpr wchar_t ProfilePictureFileName[] = L"profile-pic.img";

winrt::hstring StringValue(const json::JsonObject& object,
                           const wchar_t* name,
                           const winrt::hstring& fallback = L"")
{
    if (!object.HasKey(name))
    {
        return fallback;
    }
    const auto value = object.GetNamedValue(name);
    return value.ValueType() == json::JsonValueType::String ? value.GetString() : fallback;
}

bool BoolValue(const json::JsonObject& object, const wchar_t* name, bool fallback = false)
{
    if (!object.HasKey(name))
    {
        return fallback;
    }
    const auto value = object.GetNamedValue(name);
    return value.ValueType() == json::JsonValueType::Boolean ? value.GetBoolean() : fallback;
}

void AddDevice(std::vector<UwpDevice>& devices,
               const json::JsonObject& object,
               const winrt::hstring& groupName)
{
    UwpDevice device;
    device.Group = StringValue(object, L"Group", groupName);
    device.Name = StringValue(object, L"Name");
    device.Address = StringValue(object, L"Address");
    device.Ipv6 = StringValue(object, L"IPv6");
    device.OperatingSystem = StringValue(object, L"OS");
    device.Online = BoolValue(object, L"Online");
    device.ExitNodeOption = BoolValue(object, L"ExitNodeOption");
    if (!device.Name.empty() || !device.Address.empty())
    {
        devices.push_back(std::move(device));
    }
}

void AddDevices(std::vector<UwpDevice>& devices,
                const json::JsonArray& source,
                const winrt::hstring& groupName)
{
    for (const auto& item : source)
    {
        if (item.ValueType() == json::JsonValueType::Object)
        {
            AddDevice(devices, item.GetObject(), groupName);
        }
    }
}

std::optional<protocol::Bytes32> ReadPrivateKey(const auto& values, const wchar_t* name)
{
    const std::string hex =
        winrt::to_string(winrt::unbox_value_or<winrt::hstring>(values.TryLookup(name), L""));
    if (hex.empty())
    {
        return std::nullopt;
    }
    try
    {
        const std::vector<std::uint8_t> bytes = protocol::HexToBytes(hex);
        if (bytes.size() != protocol::Bytes32{}.size())
        {
            return std::nullopt;
        }
        protocol::Bytes32 key{};
        std::copy(bytes.begin(), bytes.end(), key.begin());
        return key;
    }
    catch (const std::runtime_error&)
    {
        return std::nullopt;
    }
}

std::optional<winrt::hstring> ReadOptional(const auto& values, const wchar_t* name)
{
    if (const auto value = values.TryLookup(name))
    {
        return winrt::unbox_value<winrt::hstring>(value);
    }
    return std::nullopt;
}

void Restore(const auto& values, const wchar_t* name, const std::optional<winrt::hstring>& setting)
{
    if (setting)
    {
        values.Insert(name, winrt::box_value(*setting));
    }
    else
    {
        values.Remove(name);
    }
}

} // namespace

SettingsControllerImpl::SettingsControllerImpl()
{
}

SettingsControllerImpl::~SettingsControllerImpl()
{
    if (m_stateWatchStarted)
    {
        storage::ApplicationData::Current().DataChanged(m_dataChangedToken);
    }
}

void SettingsControllerImpl::EnsureStateWatchStarted()
{
    if (m_stateWatchStarted)
    {
        return;
    }
    const auto coreWindow = winrt::Windows::UI::Core::CoreWindow::GetForCurrentThread();
    if (!coreWindow)
    {
        return;
    }
    m_dispatcher = coreWindow.Dispatcher();
    m_dataChangedToken = storage::ApplicationData::Current().DataChanged(
        [this](const auto&, const auto&)
        {
            if (m_dispatcher.HasThreadAccess())
            {
                Reload();
                return;
            }
            m_dispatcher.RunAsync(winrt::Windows::UI::Core::CoreDispatcherPriority::Normal,
                                  [this]()
                                  {
                                      Reload();
                                  });
        });
    m_stateWatchStarted = true;
}

const SettingsState& SettingsControllerImpl::GetState() const noexcept
{
    return m_state;
}

void SettingsControllerImpl::Reload()
{
    EnsureStateWatchStarted();
    winrt::hstring tailnetName;
    winrt::hstring tailnetDisplayName;
    winrt::hstring accountName;
    winrt::hstring accountDisplayName;
    winrt::hstring profilePicUrl;
    winrt::hstring selfAddress;
    std::vector<UwpDevice> devices;
    winrt::hstring tailgateServer;
    winrt::hstring hostname;
    winrt::hstring exitNode;
    winrt::hstring exitNodeSelection;
    winrt::hstring cachedProfilePictureUrl;
    winrt::hstring authKey;
    std::optional<protocol::Bytes32> machinePrivateKey;
    std::optional<protocol::Bytes32> nodePrivateKey;
    ConnectionSettingsSnapshot connectionSettings;
    bool registrationComplete = false;
    bool profileValidated = false;
    bool loaded = false;
    try
    {
        const auto folder = storage::ApplicationData::Current().LocalFolder().Path();
        const std::filesystem::path statePath =
            std::filesystem::path(folder.c_str()) / StateFileName;
        std::ifstream stream(statePath);
        if (stream)
        {
            const std::string text(std::istreambuf_iterator<char>(stream), {});
            json::JsonObject root{nullptr};
            if (json::JsonObject::TryParse(winrt::to_hstring(text), root))
            {
                tailnetName = StringValue(root, L"TailnetName");
                tailnetDisplayName = StringValue(root, L"TailnetDisplayName", tailnetName);
                accountName = StringValue(root, L"AccountName");
                accountDisplayName = StringValue(root, L"AccountDisplayName");
                profilePicUrl = StringValue(root, L"ProfilePicUrl");
                selfAddress = StringValue(root, L"SelfAddress");
                if (root.HasKey(L"Devices") &&
                    root.GetNamedValue(L"Devices").ValueType() == json::JsonValueType::Array)
                {
                    AddDevices(devices, root.GetNamedArray(L"Devices"), L"");
                }
                if (root.HasKey(L"DeviceGroups") &&
                    root.GetNamedValue(L"DeviceGroups").ValueType() == json::JsonValueType::Array)
                {
                    for (const auto& item : root.GetNamedArray(L"DeviceGroups"))
                    {
                        if (item.ValueType() != json::JsonValueType::Object)
                        {
                            continue;
                        }
                        const auto group = item.GetObject();
                        if (group.HasKey(L"Devices") &&
                            group.GetNamedValue(L"Devices").ValueType() ==
                                json::JsonValueType::Array)
                        {
                            AddDevices(devices,
                                       group.GetNamedArray(L"Devices"),
                                       StringValue(group, L"Name"));
                        }
                    }
                }
                loaded = !tailnetName.empty() || !tailnetDisplayName.empty() ||
                         !accountName.empty() || !devices.empty();
            }
            else
            {
                m_logger.LogWarning("tailgate-state.json is not valid JSON");
            }
        }

        const auto values = storage::ApplicationData::Current().LocalSettings().Values();
        tailgateServer =
            winrt::unbox_value_or<winrt::hstring>(values.TryLookup(L"TailgateServer"), L"");
        hostname = winrt::unbox_value_or<winrt::hstring>(values.TryLookup(L"Hostname"), L"");
        exitNode = winrt::unbox_value_or<winrt::hstring>(values.TryLookup(L"ExitNode"), L"");
        exitNodeSelection =
            winrt::unbox_value_or<winrt::hstring>(values.TryLookup(L"ExitNodeSelection"), exitNode);
        cachedProfilePictureUrl =
            winrt::unbox_value_or<winrt::hstring>(values.TryLookup(L"ProfilePictureUrl"), L"");
        authKey = winrt::unbox_value_or<winrt::hstring>(values.TryLookup(L"AuthKey"), L"");
        registrationComplete = winrt::unbox_value_or<winrt::hstring>(
                                   values.TryLookup(L"RegistrationComplete"), L"") == L"true";
        profileValidated = winrt::unbox_value_or<winrt::hstring>(
                               values.TryLookup(L"ProfileValidated"), L"") == L"true";
        machinePrivateKey = ReadPrivateKey(values, L"MachinePrivateKey");
        nodePrivateKey = ReadPrivateKey(values, L"NodePrivateKey");
        connectionSettings.TailgateServer = ReadOptional(values, L"TailgateServer");
        connectionSettings.Hostname = ReadOptional(values, L"Hostname");
        connectionSettings.ExitNode = ReadOptional(values, L"ExitNode");
        connectionSettings.ExitNodeSelection = ReadOptional(values, L"ExitNodeSelection");
    }
    catch (const winrt::hresult_error& error)
    {
        m_logger.LogError("reload failed: {}", error.message());
    }
    m_state.Update(
        [&](SettingsState& state)
        {
            state.TailnetName(std::move(tailnetName));
            state.TailnetDisplayName(std::move(tailnetDisplayName));
            state.AccountName(std::move(accountName));
            state.AccountDisplayName(std::move(accountDisplayName));
            state.ProfilePicUrl(std::move(profilePicUrl));
            state.TailgateServer(std::move(tailgateServer));
            state.Hostname(std::move(hostname));
            state.ExitNode(std::move(exitNode));
            state.ExitNodeSelection(std::move(exitNodeSelection));
            state.CachedProfilePictureUrl(std::move(cachedProfilePictureUrl));
            state.AuthKey(std::move(authKey));
            state.SelfAddress(std::move(selfAddress));
            state.MachinePrivateKey(std::move(machinePrivateKey));
            state.NodePrivateKey(std::move(nodePrivateKey));
            state.Devices(std::move(devices));
            state.ConnectionSettings(std::move(connectionSettings));
            state.RegistrationComplete(registrationComplete);
            state.ProfileValidated(profileValidated);
            state.HasStoredProfile(profileValidated && !state.TailgateServer().empty());
            state.Loaded(loaded);
        });
}

void SettingsControllerImpl::Clear()
{
    const auto values = storage::ApplicationData::Current().LocalSettings().Values();
    for (const auto* name : {L"MachinePrivateKey",
                             L"NodePrivateKey",
                             L"DiscoPrivateKey",
                             L"RegistrationComplete",
                             L"ProfileValidated",
                             L"NodeAuthUrl",
                             L"NodeAuthTailgateServer",
                             L"NodeAuthorizationKind",
                             L"NodeFollowupUrl",
                             L"AuthKey",
                             L"TailgateServer",
                             L"Hostname",
                             L"ExitNode",
                             L"ExitNodeSelection",
                             L"ProfilePictureUrl",
                             L"PinnedRelayServer",
                             L"PinnedRelayPublicKey",
                             L"RelayResolution",
                             L"PendingExitNodeChange",
                             L"NetworkPolicyRestartRequired"})
    {
        values.Remove(name);
    }
    const auto folder = storage::ApplicationData::Current().LocalFolder().Path();
    for (const auto* file : {StateFileName, ProfilePictureFileName})
    {
        std::error_code error;
        (void)std::filesystem::remove(std::filesystem::path(folder.c_str()) / file, error);
        if (error)
        {
            m_logger.LogWarning("failed to remove persisted file: {}", error.message());
        }
    }
    Reload();
}

void SettingsControllerImpl::SetHostname(const winrt::hstring& hostname)
{
    const auto values = storage::ApplicationData::Current().LocalSettings().Values();
    if (hostname.empty())
    {
        values.Remove(L"Hostname");
    }
    else
    {
        values.Insert(L"Hostname", winrt::box_value(hostname));
    }
    Reload();
}

void SettingsControllerImpl::SetTailgateServer(const winrt::hstring& tailgateServer)
{
    storage::ApplicationData::Current().LocalSettings().Values().Insert(
        L"TailgateServer", winrt::box_value(tailgateServer));
    Reload();
}

void SettingsControllerImpl::SetAuthentication(const winrt::hstring& tailgateServer,
                                               const winrt::hstring& authKey)
{
    const auto values = storage::ApplicationData::Current().LocalSettings().Values();
    values.Insert(L"TailgateServer", winrt::box_value(tailgateServer));
    if (!authKey.empty())
    {
        values.Insert(L"AuthKey", winrt::box_value(authKey));
    }
    Reload();
}

void SettingsControllerImpl::SetExitNode(const winrt::hstring& exitNode, bool preserveSelection)
{
    const auto values = storage::ApplicationData::Current().LocalSettings().Values();
    values.Insert(L"ExitNode", winrt::box_value(exitNode));
    if (!preserveSelection || !exitNode.empty())
    {
        values.Insert(L"ExitNodeSelection", winrt::box_value(exitNode));
    }
    Reload();
}

void SettingsControllerImpl::SetCachedProfilePictureUrl(const winrt::hstring& url)
{
    storage::ApplicationData::Current().LocalSettings().Values().Insert(L"ProfilePictureUrl",
                                                                        winrt::box_value(url));
    Reload();
}

void SettingsControllerImpl::ClearCachedProfilePictureUrl()
{
    storage::ApplicationData::Current().LocalSettings().Values().Remove(L"ProfilePictureUrl");
    Reload();
}

void SettingsControllerImpl::RestoreConnectionSettings(const ConnectionSettingsSnapshot& settings)
{
    const auto values = storage::ApplicationData::Current().LocalSettings().Values();
    Restore(values, L"TailgateServer", settings.TailgateServer);
    Restore(values, L"Hostname", settings.Hostname);
    Restore(values, L"ExitNode", settings.ExitNode);
    Restore(values, L"ExitNodeSelection", settings.ExitNodeSelection);
    Reload();
}

} // namespace tailgate::uwp
