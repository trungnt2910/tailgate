#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/ByteStream.h>
#include <tailgate/control/NetworkMap.h>
#include <tailgate/protocol/ControlRequests.h>
#include <tailgate/protocol/Crypto.h>

namespace tailgate::control
{

struct FeatureEnablement
{
    bool Complete = false;
    bool ShouldWait = false;
    std::string Text;
    std::string Url;
};

struct ExternalNodePublicKey
{
    protocol::Bytes32 Value{};
};

enum class RegistrationState
{
    Complete,
    LoginRequired,
    MachineApprovalRequired,
};

struct RegistrationResult
{
    RegistrationState State = RegistrationState::Complete;
    std::string AuthorizationUrl;
    std::string AuthorizationCode;
    std::string ApprovalUrl;
    std::optional<NetworkConfig> Network;
    bool NetworkMapStreaming = false;
};

struct RegistrationOptions
{
    std::string InitialFollowupUrl;
    std::string ReauthorizationKey;
    std::function<void(const RegistrationResult&)> StateChanged;
    std::function<bool(std::chrono::milliseconds)> WaitForRetry;
};

class ControlClient
{
public:
    ControlClient(IByteStream& stream,
                  const protocol::Bytes32& machinePrivateKey,
                  const protocol::Bytes32& nodePrivateKey,
                  const protocol::HostInfo& host);
    ControlClient(IByteStream& stream,
                  const protocol::Bytes32& machinePrivateKey,
                  ExternalNodePublicKey nodePublicKey,
                  const protocol::HostInfo& host);
    ~ControlClient();
    ControlClient(ControlClient&&) noexcept;
    ControlClient& operator=(ControlClient&&) noexcept;
    ControlClient(const ControlClient&) = delete;
    ControlClient& operator=(const ControlClient&) = delete;

    [[nodiscard]] RegistrationResult Register(const std::string& authKey = {},
                                              const std::string& followupUrl = {});
    [[nodiscard]] RegistrationResult
    RegisterUntilAuthorized(const std::string& authKey,
                            const RegistrationOptions& options = RegistrationOptions{});
    [[nodiscard]] NetworkConfig RequestNetworkMap();
    [[nodiscard]] FeatureEnablement QueryFeature(const std::string& feature);
    void SetDnsTxt(const std::string& name, const std::string& value);
    void UpdateHostInfo(int preferredDerp = 0);
    void SetDiscoPrivateKey(const protocol::Bytes32& privateKey);
    void SetEndpoints(std::vector<protocol::MapEndpoint> endpoints);
    void SetPreferredDerp(int region);
    [[nodiscard]] std::optional<NetworkConfig> PollNetworkMap();
    [[nodiscard]] NetworkConfig WaitForNetworkMap();
    void Logout();
    [[nodiscard]] const protocol::Bytes32& NodePublicKey() const;
    [[nodiscard]] const protocol::Bytes32& DiscoPrivateKey() const;

private:
    class Impl;
    std::unique_ptr<Impl> Implementation;
};

} // namespace tailgate::control
