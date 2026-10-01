#include "TailgateRelay.h"

#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/hosted/RelayEndpoint.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/nettype/TcpSocket.h>

#include "TcpSocketFactory.h"

namespace tailgate::uwp
{

TailgateRelay::TailgateRelay(std::string host, std::string service)
    : m_requestHost(std::move(host)), m_validationHost(m_requestHost), m_service(std::move(service))
{
    if (m_requestHost.empty() || m_service.empty())
    {
        throw std::invalid_argument("Tailgate relay endpoint is incomplete.");
    }
}

void TailgateRelay::Resolve(const std::optional<std::string>& networkInterface,
                            std::stop_token cancellation)
{
    TcpSocketFactory socketFactory;
    tailgate::hosted::RelayEndpoint endpoint{
        .Host = m_requestHost, .ConnectAddress = {}, .Port = m_service};
    endpoint.Resolve(socketFactory, networkInterface, 0, cancellation, false);
    m_validationHost = std::move(endpoint.Host);
    m_connectAddress = std::move(endpoint.ConnectAddress);
    m_usingCachedEndpoint = false;
}

void TailgateRelay::UseCachedEndpoint(std::string connectAddress, std::string validationHost)
{
    if (!tailgate::net::Ipv4Address::TryParse(connectAddress) || validationHost.empty())
    {
        throw std::invalid_argument("Cached Tailgate relay endpoint is invalid.");
    }
    m_connectAddress = std::move(connectAddress);
    m_validationHost = std::move(validationHost);
    m_usingCachedEndpoint = true;
}

void TailgateRelay::Preflight(std::chrono::seconds timeout)
{
    Resolve();
    TcpSocketFactory socketFactory;
    std::unique_ptr<tailgate::types::nettype::TcpSocket> stream =
        socketFactory.OpenTcpSocket(tailgate::types::nettype::TcpSocketOptions{
            .ConnectAddress = m_connectAddress,
            .Service = m_service,
            .NetworkInterface = std::nullopt,
            .TlsServerName = m_validationHost,
            .IoTimeout = timeout,
            .ConnectTimeout = std::nullopt,
            .ReadinessToken = {},
            .AllowTls13 = false,
            .NonBlockingAfterConnect = false,
        });
    tailgate::hosted::Decoder decoder;
    decoder.Feed(tailgate::hosted::RequestHttpUpgrade(
        *stream, std::format("{}:{}", m_requestHost, m_service)));
    const tailgate::hosted::Frame challengeFrame = decoder.Read(*stream);
    if (challengeFrame.Type() != tailgate::hosted::MessageType::ServerChallenge)
    {
        throw std::runtime_error("Tailgate server did not provide an identity challenge.");
    }
    (void)tailgate::hosted::ProtocolCodec::DecodeChallenge(challengeFrame.Payload());
    stream->Close();
}

const std::string& TailgateRelay::Host() const noexcept
{
    return m_validationHost;
}

const std::string& TailgateRelay::Service() const noexcept
{
    return m_service;
}

const std::string& TailgateRelay::ConnectAddress() const noexcept
{
    return m_connectAddress;
}

bool TailgateRelay::IsUsingCachedEndpoint() const noexcept
{
    return m_usingCachedEndpoint;
}

} // namespace tailgate::uwp
