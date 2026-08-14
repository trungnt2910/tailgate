#include "TailgateRelay.h"

#include <cstdint>
#include <format>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <winrt/Windows.Networking.Sockets.h>

#include <tailgate/base/ByteStream.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/packet/Ipv4.h>

#include "UwpTcpStream.h"

namespace tailgate::uwp
{

namespace
{

namespace sockets = winrt::Windows::Networking::Sockets;

constexpr std::string_view PublicDnsAddress = "1.1.1.1";
constexpr std::string_view PublicDnsTlsName = "cloudflare-dns.com";
constexpr std::string_view DnsOverTlsService = "853";
constexpr std::size_t MaximumCanonicalDnsQueries = 8;
constexpr std::size_t DnsMessageLengthSize = 2;
constexpr std::chrono::seconds DnsConnectTimeout(20);

std::vector<std::uint8_t> ReadTlsExact(tailgate::base::IByteStream& tls, std::size_t byteCount)
{
    std::vector<std::uint8_t> result;
    result.reserve(byteCount);
    while (result.size() < byteCount)
    {
        std::optional<std::vector<std::uint8_t>> part = tls.TryReadSome(byteCount - result.size());
        if (!part)
        {
            continue;
        }
        if (part->empty())
        {
            throw std::runtime_error("TLS stream closed before enough bytes were read.");
        }
        result.insert(result.end(), part->begin(), part->end());
    }
    return result;
}

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
    if (tailgate::net::packet::ParseIpv4(m_validationHost))
    {
        m_connectAddress = m_validationHost;
        return;
    }
    UwpTcpStream dnsTls(sockets::StreamSocket(),
                        std::string(PublicDnsAddress),
                        std::string(DnsOverTlsService),
                        sockets::SocketProtectionLevel::Tls12,
                        DnsConnectTimeout,
                        std::string(PublicDnsTlsName));
    const auto queryDns = [&dnsTls](const std::string& current)
    {
        const tailgate::crypto::Bytes32 random = tailgate::crypto::GeneratePrivateKey();
        const std::uint16_t transaction = (static_cast<std::uint16_t>(random[0]) << 8U) | random[1];
        std::vector<std::uint8_t> query = tailgate::net::dns::BuildDnsQuery(current, transaction);
        query.insert(query.begin(),
                     {static_cast<std::uint8_t>(query.size() >> 8U),
                      static_cast<std::uint8_t>(query.size())});
        dnsTls.WriteAll(query);
        const std::vector<std::uint8_t> length = ReadTlsExact(dnsTls, DnsMessageLengthSize);
        const std::size_t responseSize = (static_cast<std::size_t>(length[0]) << 8U) | length[1];
        return tailgate::net::dns::ParseDnsAnswer(
            ReadTlsExact(dnsTls, responseSize), transaction, current);
    };
    const tailgate::crypto::Bytes32 random = tailgate::crypto::GeneratePrivateKey();
    const tailgate::net::dns::DnsTarget target = tailgate::net::dns::ResolveDnsTarget(
        m_validationHost, queryDns, random[0], MaximumCanonicalDnsQueries);
    m_validationHost = target.ValidationName;
    m_connectAddress = target.ConnectAddress;
    m_logger.LogInfo("relay resolution name={} address={}", m_validationHost, m_connectAddress);
}

void TailgateRelay::UseCachedEndpoint(std::string connectAddress, std::string validationHost)
{
    if (!tailgate::net::packet::ParseIpv4(connectAddress) || validationHost.empty())
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
    UwpTcpStream stream(sockets::StreamSocket(),
                        m_connectAddress,
                        m_service,
                        sockets::SocketProtectionLevel::Tls12,
                        timeout,
                        m_validationHost);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(tailgate::hosted::RequestHttpUpgrade(
        stream, std::format("{}:{}", m_requestHost, m_service)));
    const tailgate::hosted::Frame challengeFrame = tailgate::hosted::ReadFrame(stream, decoder);
    if (challengeFrame.Type != tailgate::hosted::MessageType::ServerChallenge)
    {
        throw std::runtime_error("Tailgate server did not provide an identity challenge.");
    }
    (void)tailgate::hosted::DecodeChallenge(challengeFrame.Payload);
    stream.Close();
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
