#include "ClientImpl.h"

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <tailgate/base/Logger.h>

namespace tailgate::net::http::impl
{
namespace
{

constexpr std::size_t ReadBufferSize = 16U * 1024U;
// This finite-body API serves control/ACME documents. Taildrive uses the incremental parser
// directly and is not subject to this in-memory document limit.
constexpr std::size_t MaximumResponseSize = 64U * 1024U * 1024U;

} // namespace

ClientImpl::ClientImpl(tailgate::types::nettype::TcpSocketFactory& socketFactory,
                       MessageParserFactory& parserFactory) noexcept
    : m_socketFactory(socketFactory), m_parserFactory(parserFactory)
{
}

Response ClientImpl::Send(const Request& request)
{
    const HttpsUrl url = HttpsUrl::Parse(request.Url());
    tailgate::base::Logger("http").LogDebug(
        "sending HTTPS request host={} service={} path={}", url.Host(), url.Service(), url.Path());
    std::unique_ptr<tailgate::types::nettype::TcpSocket> socket =
        m_socketFactory.OpenTcpSocket(tailgate::types::nettype::TcpSocketOptions{
            .ConnectAddress = url.Host(),
            .Service = url.Service(),
            .NetworkInterface = std::nullopt,
            .TlsServerName = url.Host(),
            .IoTimeout = std::chrono::seconds(20),
            .ConnectTimeout = std::nullopt,
            .ReadinessToken = {},
            .AllowTls13 = true,
            .NonBlockingAfterConnect = false,
        });
    const std::string encoded = request.Encode();
    socket->WriteAll(std::vector<std::uint8_t>(encoded.begin(), encoded.end()));
    std::string response;
    while (true)
    {
        const std::vector<std::uint8_t> part = socket->ReadSome(ReadBufferSize);
        if (part.empty())
        {
            break;
        }
        if (part.size() > MaximumResponseSize - response.size())
        {
            throw MessageError(MessageErrorKind::BodyLimit);
        }
        response.append(reinterpret_cast<const char*>(part.data()), part.size());
    }
    tailgate::base::Logger("http").LogTrace("received HTTPS response bytes={}", response.size());
    auto parser = m_parserFactory.Create(
        ParserOptions{.Kind = MessageKind::Response, .SkipBody = request.Method() == "HEAD"});
    return parser->DecodeResponse(response);
}

} // namespace tailgate::net::http::impl
