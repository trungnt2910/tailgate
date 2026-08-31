#pragma once

#include <memory>
#include <string>
#include <vector>

#include <tailgate/base/EventLoop.h>
#include <tailgate/control/client/Session.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::control::client
{

enum class ConnectionEventStatus
{
    Ready,
    Disconnected,
};

struct ConnectionEventResult
{
    bool Handled = false;
    ConnectionEventStatus Status = ConnectionEventStatus::Ready;
    std::vector<tailgate::types::netmap::NetworkConfig> NetworkMaps;
};

class Connection
{
public:
    virtual ~Connection();

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
    virtual void StartStreaming() = 0;
    [[nodiscard]] virtual ConnectionEventResult
    ProcessEvent(const tailgate::base::Event& event) = 0;
    [[nodiscard]] virtual std::vector<tailgate::types::netmap::NetworkConfig> Maintain() = 0;
    virtual void RequestReconnect() noexcept = 0;
    virtual void Logout() = 0;
    [[nodiscard]] virtual const tailgate::crypto::Bytes32& NodePublicKey() const = 0;
    [[nodiscard]] virtual const tailgate::crypto::Bytes32& DiscoPrivateKey() const = 0;
    [[nodiscard]] virtual bool Connected() const noexcept = 0;
};

class ConnectionFactory
{
public:
    virtual ~ConnectionFactory();

    [[nodiscard]] virtual std::unique_ptr<Connection> CreateConnection(SessionOptions options) = 0;
};

} // namespace tailgate::control::client
