#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/base/ByteStream.h>
#include <tailgate/control/client/ControlRequests.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::control::client
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
    tailgate::crypto::Bytes32 Value{};
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
    std::optional<tailgate::types::netmap::NetworkConfig> Network;
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
    ControlClient(tailgate::base::IByteStream& stream,
                  const tailgate::crypto::Bytes32& machinePrivateKey,
                  const tailgate::crypto::Bytes32& nodePrivateKey,
                  const tailgate::control::client::HostInfo& host);
    ControlClient(tailgate::base::IByteStream& stream,
                  const tailgate::crypto::Bytes32& machinePrivateKey,
                  ExternalNodePublicKey nodePublicKey,
                  const tailgate::control::client::HostInfo& host);
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
    [[nodiscard]] tailgate::types::netmap::NetworkConfig RequestNetworkMap();
    [[nodiscard]] FeatureEnablement QueryFeature(const std::string& feature);
    void SetDnsTxt(const std::string& name, const std::string& value);
    void UpdateHostInfo(int preferredDerp = 0);
    void SetDiscoPrivateKey(const tailgate::crypto::Bytes32& privateKey);
    void SetEndpoints(std::vector<tailgate::control::client::MapEndpoint> endpoints);
    void SetPreferredDerp(int region);
    [[nodiscard]] std::optional<tailgate::types::netmap::NetworkConfig> PollNetworkMap();
    [[nodiscard]] tailgate::types::netmap::NetworkConfig WaitForNetworkMap();
    void Logout();
    [[nodiscard]] const tailgate::crypto::Bytes32& NodePublicKey() const;
    [[nodiscard]] const tailgate::crypto::Bytes32& DiscoPrivateKey() const;

private:
    class Impl;
    std::unique_ptr<Impl> Implementation;
};

} // namespace tailgate::control::client
