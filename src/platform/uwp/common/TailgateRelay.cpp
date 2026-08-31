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
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/nettype/TcpSocket.h>

#include "TcpSocketFactory.h"

namespace tailgate::uwp
{

namespace
{

constexpr std::size_t MaximumCanonicalDnsQueries = 8;
constexpr std::chrono::seconds DnsConnectTimeout(20);
constexpr std::string_view PublicDnsAddress = "1.1.1.1";
constexpr std::string_view PublicDnsTlsName = "cloudflare-dns.com";
constexpr std::string_view DnsOverTlsService = "853";

} // namespace

TailgateRelay::TailgateRelay(std::string host, std::string service)
    : m_requestHost(std::move(host)), m_validationHost(m_requestHost), m_service(std::move(service))
{
    if (m_requestHost.empty() || m_service.empty())
    {
        throw std::invalid_argument("Tailgate relay endpoint is incomplete.");
    }
}

void TailgateRelay::Resolve()
{
    m_usingCachedEndpoint = false;
    m_validationHost = m_requestHost;
    m_connectAddress.clear();
    if (tailgate::net::Ipv4Address::TryParse(m_validationHost))
    {
        m_connectAddress = m_validationHost;
        return;
    }
    TcpSocketFactory socketFactory;
    std::unique_ptr<tailgate::types::nettype::TcpSocket> dnsTls =
        socketFactory.OpenTcpSocket(tailgate::types::nettype::TcpSocketOptions{
            .ConnectAddress = std::string(PublicDnsAddress),
            .Service = std::string(DnsOverTlsService),
            .NetworkInterface = std::nullopt,
            .TlsServerName = std::string(PublicDnsTlsName),
            .IoTimeout = DnsConnectTimeout,
            .ConnectTimeout = std::nullopt,
            .ReadinessToken = {},
            .AllowTls13 = false,
            .NonBlockingAfterConnect = false,
        });
    const tailgate::crypto::Bytes32 random = tailgate::crypto::GeneratePrivateKey();
    const tailgate::net::dns::DnsTarget target = tailgate::net::dns::ResolveDnsOverTlsTarget(
        *dnsTls, m_validationHost, random[0], MaximumCanonicalDnsQueries);
    m_validationHost = target.ValidationName;
    m_connectAddress = target.ConnectAddress;
    m_logger.LogInfo("relay resolution name={} address={}", m_validationHost, m_connectAddress);
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
