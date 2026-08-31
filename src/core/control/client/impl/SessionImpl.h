#pragma once

#include <memory>

#include <tailgate/control/client/HostInfoProvider.h>
#include <tailgate/control/client/Session.h>

namespace tailgate::control::client::impl
{

class SessionImpl final : public tailgate::control::client::Session
{
public:
    SessionImpl(tailgate::control::client::SessionOptions options,
                tailgate::types::nettype::TcpSocketFactory& socketFactory);
    ~SessionImpl() override;

    [[nodiscard]] tailgate::control::client::RegistrationResult
    RegisterUntilAuthorized(const std::string& authKey,
                            const tailgate::control::client::RegistrationOptions& options) override;
    [[nodiscard]] tailgate::types::netmap::NetworkConfig RequestNetworkMap() override;
    [[nodiscard]] tailgate::control::client::FeatureEnablement
    QueryFeature(const std::string& feature) override;
    void SetDnsTxt(const std::string& name, const std::string& value) override;
    void UpdateHostInfo(int preferredDerp) override;
    void SetDiscoPrivateKey(const tailgate::crypto::Bytes32& privateKey) override;
    void SetEndpoints(std::vector<tailgate::control::client::MapEndpoint> endpoints) override;
    void SetPreferredDerp(int region) override;
    [[nodiscard]] std::optional<tailgate::types::netmap::NetworkConfig> PollNetworkMap() override;
    [[nodiscard]] tailgate::types::netmap::NetworkConfig WaitForNetworkMap() override;
    void SetReadTimeout(std::optional<std::chrono::seconds> timeout) override;
    void SetWriteInterest(bool enabled) override;
    void SetNonBlocking(bool enabled) override;
    [[nodiscard]] bool ReadNeedsWrite() const override;
    [[nodiscard]] bool HasPendingOutput() const override;
    void Close() noexcept override;
    void Logout() override;
    [[nodiscard]] const tailgate::crypto::Bytes32& NodePublicKey() const override;
    [[nodiscard]] const tailgate::crypto::Bytes32& DiscoPrivateKey() const override;

private:
    [[nodiscard]] tailgate::control::client::ControlClient& Client();
    [[nodiscard]] const tailgate::control::client::ControlClient& Client() const;

    std::unique_ptr<tailgate::types::nettype::TcpSocket> m_socket;
    std::unique_ptr<tailgate::control::client::ControlClient> m_client;
};

class SessionFactoryImpl final : public tailgate::control::client::SessionFactory
{
public:
    explicit SessionFactoryImpl(tailgate::control::client::HostInfoProvider& hostInfoProvider)
        : m_hostInfoProvider(hostInfoProvider)
    {
    }

    [[nodiscard]] std::unique_ptr<tailgate::control::client::Session>
    CreateSession(tailgate::control::client::SessionOptions options,
                  tailgate::types::nettype::TcpSocketFactory& socketFactory) override;

private:
    tailgate::control::client::HostInfoProvider& m_hostInfoProvider;
};

} // namespace tailgate::control::client::impl
