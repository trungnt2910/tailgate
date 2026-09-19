#include "SessionImpl.h"

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include <tailgate/control/base/ControlHandshake.h>

#include "ControlDialer.h"

namespace tailgate::control::client::impl
{
namespace
{

class SessionControlDialer final : public ControlDialer
{
public:
    SessionControlDialer(const tailgate::control::client::SessionOptions& options,
                         tailgate::types::nettype::TcpSocketFactory& socketFactory)
        : m_options(options), m_socketFactory(socketFactory)
    {
    }

    std::unique_ptr<tailgate::types::nettype::TcpSocket> Open(bool tls) override
    {
        std::optional<std::string> networkInterface;
        if (!m_options.NetworkInterface.empty())
        {
            networkInterface = m_options.NetworkInterface;
        }
        return m_socketFactory.OpenTcpSocket(tailgate::types::nettype::TcpSocketOptions{
            .ConnectAddress = tailgate::control::base::ControlHandshake::DefaultHost,
            .Service = tls ? tailgate::control::base::ControlHandshake::TlsService
                           : tailgate::control::base::ControlHandshake::PlaintextService,
            .NetworkInterface = std::move(networkInterface),
            .TlsServerName = tls ? std::optional<std::string>(
                                       tailgate::control::base::ControlHandshake::DefaultHost)
                                 : std::nullopt,
            .IoTimeout = m_options.IoTimeout,
            .ConnectTimeout =
                tls ? std::nullopt
                    : std::optional<std::chrono::seconds>(m_options.PlaintextConnectTimeout),
            .ReadinessToken = m_options.ReadinessToken,
            .AllowTls13 = false,
            .NonBlockingAfterConnect = false,
        });
    }

    std::unique_ptr<tailgate::control::client::ControlClient>
    Establish(tailgate::base::ByteStream& stream) override
    {
        return m_options.ExternalNodePublicKey
                   ? std::make_unique<tailgate::control::client::ControlClient>(
                         stream,
                         m_options.MachinePrivateKey,
                         tailgate::control::client::ExternalNodePublicKey{
                             .Value = *m_options.ExternalNodePublicKey},
                         m_options.Host)
                   : std::make_unique<tailgate::control::client::ControlClient>(
                         stream,
                         m_options.MachinePrivateKey,
                         m_options.NodePrivateKey,
                         m_options.Host);
    }

private:
    const tailgate::control::client::SessionOptions& m_options;
    tailgate::types::nettype::TcpSocketFactory& m_socketFactory;
};

} // namespace

SessionImpl::SessionImpl(std::unique_ptr<tailgate::types::nettype::TcpSocket> socket,
                         std::unique_ptr<tailgate::control::client::ControlClient> client)
    : m_socket(std::move(socket)), m_client(std::move(client))
{
}

SessionImpl::~SessionImpl()
{
    Close();
}

tailgate::control::client::RegistrationResult
SessionImpl::RegisterUntilAuthorized(const std::string& authKey,
                                     const tailgate::control::client::RegistrationOptions& options)
{
    return Client().RegisterUntilAuthorized(authKey, options);
}

tailgate::types::netmap::NetworkConfig SessionImpl::RequestNetworkMap()
{
    return Client().RequestNetworkMap();
}

tailgate::control::client::FeatureEnablement SessionImpl::QueryFeature(const std::string& feature)
{
    return Client().QueryFeature(feature);
}

void SessionImpl::SetDnsTxt(const std::string& name, const std::string& value)
{
    Client().SetDnsTxt(name, value);
}

void SessionImpl::UpdateHostInfo(int preferredDerp)
{
    Client().UpdateHostInfo(preferredDerp);
}

void SessionImpl::SetDiscoPrivateKey(const tailgate::crypto::Bytes32& privateKey)
{
    Client().SetDiscoPrivateKey(privateKey);
}

void SessionImpl::SetEndpoints(std::vector<tailgate::control::client::MapEndpoint> endpoints)
{
    Client().SetEndpoints(std::move(endpoints));
}

void SessionImpl::SetPreferredDerp(int region)
{
    Client().SetPreferredDerp(region);
}

std::optional<tailgate::types::netmap::NetworkConfig> SessionImpl::PollNetworkMap()
{
    return Client().PollNetworkMap();
}

tailgate::types::netmap::NetworkConfig SessionImpl::WaitForNetworkMap()
{
    return Client().WaitForNetworkMap();
}

void SessionImpl::SetReadTimeout(std::optional<std::chrono::seconds> timeout)
{
    if (!m_closed && m_socket)
    {
        m_socket->SetReadTimeout(timeout);
    }
}

void SessionImpl::SetWriteInterest(bool enabled)
{
    if (!m_closed && m_socket)
    {
        m_socket->SetWriteInterest(enabled);
    }
}

void SessionImpl::SetNonBlocking(bool enabled)
{
    if (!m_closed && m_socket)
    {
        m_socket->SetNonBlocking(enabled);
    }
}

bool SessionImpl::ReadNeedsWrite() const
{
    return !m_closed && m_socket && m_socket->ReadNeedsWrite();
}

bool SessionImpl::HasPendingOutput() const
{
    return !m_closed && m_client && m_client->HasPendingOutput();
}

void SessionImpl::Close() noexcept
{
    if (m_closed.exchange(true))
    {
        return;
    }
    // WaitForNetworkMap may still be using the client and its stream on the maintenance
    // thread. Closing cancels its I/O; destruction belongs after the owner joins that thread.
    if (m_socket)
    {
        m_socket->Close();
    }
}

void SessionImpl::Logout()
{
    Client().Logout();
}

const tailgate::crypto::Bytes32& SessionImpl::NodePublicKey() const
{
    return Client().NodePublicKey();
}

const tailgate::crypto::Bytes32& SessionImpl::DiscoPrivateKey() const
{
    return Client().DiscoPrivateKey();
}

tailgate::control::client::ControlClient& SessionImpl::Client()
{
    if (m_closed || !m_client)
    {
        throw std::logic_error("The control session is unavailable.");
    }
    return *m_client;
}

const tailgate::control::client::ControlClient& SessionImpl::Client() const
{
    if (m_closed || !m_client)
    {
        throw std::logic_error("The control session is unavailable.");
    }
    return *m_client;
}

std::unique_ptr<tailgate::control::client::Session>
SessionFactoryImpl::CreateSession(tailgate::control::client::SessionOptions options,
                                  tailgate::types::nettype::TcpSocketFactory& socketFactory)
{
    tailgate::control::client::HostInfo host = m_hostInfoProvider.GetHostInfo();
    host.ApplySessionConfig(std::move(options.Host));
    options.Host = std::move(host);
    SessionControlDialer dialer(options, socketFactory);
    ControlDialOutcome outcome = dialer.Dial();
    m_logger.LogInfo("connected tls={}", outcome.UsedTls ? 1 : 0);
    return std::make_unique<SessionImpl>(std::move(outcome.Stream), std::move(outcome.Client));
}

} // namespace tailgate::control::client::impl
