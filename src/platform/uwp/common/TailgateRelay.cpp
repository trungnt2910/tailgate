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

#include <tailgate/ByteStream.h>
#include <tailgate/network/Dns.h>
#include <tailgate/network/Ipv4.h>
#include <tailgate/protocol/Crypto.h>
#include <tailgate/relay/RelayProtocol.h>

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

std::vector<std::uint8_t> ReadTlsExact(IByteStream& tls, std::size_t byteCount)
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
    if (network::ParseIpv4(m_validationHost))
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
        const protocol::Bytes32 random = protocol::GeneratePrivateKey();
        const std::uint16_t transaction = (static_cast<std::uint16_t>(random[0]) << 8U) | random[1];
        std::vector<std::uint8_t> query = network::BuildDnsQuery(current, transaction);
        query.insert(query.begin(),
                     {static_cast<std::uint8_t>(query.size() >> 8U),
                      static_cast<std::uint8_t>(query.size())});
        dnsTls.WriteAll(query);
        const std::vector<std::uint8_t> length = ReadTlsExact(dnsTls, DnsMessageLengthSize);
        const std::size_t responseSize = (static_cast<std::size_t>(length[0]) << 8U) | length[1];
        return network::ParseDnsAnswer(ReadTlsExact(dnsTls, responseSize), transaction, current);
    };
    const protocol::Bytes32 random = protocol::GeneratePrivateKey();
    const network::DnsTarget target = network::ResolveDnsTarget(
        m_validationHost, queryDns, random[0], MaximumCanonicalDnsQueries);
    m_validationHost = target.ValidationName;
    m_connectAddress = target.ConnectAddress;
    m_logger.LogInfo("relay resolution name={} address={}", m_validationHost, m_connectAddress);
}

void TailgateRelay::UseCachedEndpoint(std::string connectAddress, std::string validationHost)
{
    if (!network::ParseIpv4(connectAddress) || validationHost.empty())
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
    tailgate::relay::Decoder decoder;
    decoder.Feed(tailgate::relay::RequestHttpUpgrade(
        stream, std::format("{}:{}", m_requestHost, m_service)));
    const tailgate::relay::Frame challengeFrame = tailgate::relay::ReadFrame(stream, decoder);
    if (challengeFrame.Type != tailgate::relay::MessageType::ServerChallenge)
    {
        throw std::runtime_error("Tailgate server did not provide an identity challenge.");
    }
    (void)tailgate::relay::DecodeChallenge(challengeFrame.Payload);
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
