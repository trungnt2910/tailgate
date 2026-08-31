#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/base/EventLoop.h>
#include <tailgate/control/client/ControlClient.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/types/netmap/NetworkMap.h>
#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::control::client
{

struct SessionOptions
{
    tailgate::control::client::HostInfo Host;
    tailgate::crypto::Bytes32 MachinePrivateKey{};
    tailgate::crypto::Bytes32 NodePrivateKey{};
    std::optional<tailgate::crypto::Bytes32> ExternalNodePublicKey;
    std::string NetworkInterface;
    tailgate::base::EventToken ReadinessToken;
    std::chrono::seconds IoTimeout{20};
    std::chrono::seconds PlaintextConnectTimeout{5};
};

class Session
{
public:
    virtual ~Session();

    [[nodiscard]] virtual RegistrationResult
    RegisterUntilAuthorized(const std::string& authKey,
                            const RegistrationOptions& options = RegistrationOptions{}) = 0;
    [[nodiscard]] virtual tailgate::types::netmap::NetworkConfig RequestNetworkMap() = 0;
    [[nodiscard]] virtual FeatureEnablement QueryFeature(const std::string& feature) = 0;
    virtual void SetDnsTxt(const std::string& name, const std::string& value) = 0;
    virtual void UpdateHostInfo(int preferredDerp = 0) = 0;
    virtual void SetDiscoPrivateKey(const tailgate::crypto::Bytes32& privateKey) = 0;
    virtual void SetEndpoints(std::vector<MapEndpoint> endpoints) = 0;
    virtual void SetPreferredDerp(int region) = 0;
    [[nodiscard]] virtual std::optional<tailgate::types::netmap::NetworkConfig>
    PollNetworkMap() = 0;
    [[nodiscard]] virtual tailgate::types::netmap::NetworkConfig WaitForNetworkMap() = 0;
    virtual void SetReadTimeout(std::optional<std::chrono::seconds> timeout) = 0;
    virtual void SetWriteInterest(bool enabled) = 0;
    virtual void SetNonBlocking(bool enabled) = 0;
    [[nodiscard]] virtual bool ReadNeedsWrite() const = 0;
    [[nodiscard]] virtual bool HasPendingOutput() const = 0;
    virtual void Close() noexcept = 0;
    virtual void Logout() = 0;
    [[nodiscard]] virtual const tailgate::crypto::Bytes32& NodePublicKey() const = 0;
    [[nodiscard]] virtual const tailgate::crypto::Bytes32& DiscoPrivateKey() const = 0;
};

class SessionFactory
{
public:
    virtual ~SessionFactory();

    [[nodiscard]] virtual std::unique_ptr<Session>
    CreateSession(SessionOptions options,
                  tailgate::types::nettype::TcpSocketFactory& socketFactory) = 0;
};

} // namespace tailgate::control::client
