#include "tailgate/net/http/Client.h"

#include <cstddef>
#include <format>
#include <string_view>

namespace tailgate::net::http
{
namespace
{

constexpr std::string_view HttpsPrefix = "https://";

const char* ErrorMessage(CodecErrorKind kind)
{
    switch (kind)
    {
    case CodecErrorKind::InvalidUrl:
        return "HTTPS URL is invalid";
    }
    return "HTTP codec failed";
}

} // namespace

CodecError::CodecError(CodecErrorKind kind) : std::runtime_error(ErrorMessage(kind)), m_kind(kind)
{
}

CodecErrorKind CodecError::Kind() const noexcept
{
    return m_kind;
}

Client::~Client() = default;

HttpsUrl HttpsUrl::Parse(const std::string& url)
{
    if (!url.starts_with(HttpsPrefix))
    {
        throw CodecError(CodecErrorKind::InvalidUrl);
    }
    const std::size_t slash = url.find('/', HttpsPrefix.size());
    const std::string authority = url.substr(HttpsPrefix.size(), slash - HttpsPrefix.size());
    const std::size_t colon = authority.rfind(':');
    const std::string host = colon == std::string::npos ? authority : authority.substr(0, colon);
    const std::string service = colon == std::string::npos ? "443" : authority.substr(colon + 1);
    const std::string path = slash == std::string::npos ? "/" : url.substr(slash);
    if (host.empty() || service.empty())
    {
        throw CodecError(CodecErrorKind::InvalidUrl);
    }
    return HttpsUrl(host, service, path);
}

std::string Request::Encode() const
{
    const HttpsUrl url = HttpsUrl::Parse(m_url);
    MessageHead head;
    head.Method(m_method);
    head.Target(url.Path());
    head.Fields(
        {{"Host",
          url.Service() == "443" ? url.Host() : std::format("{}:{}", url.Host(), url.Service())},
         {"Connection", "close"},
         {"Content-Length", std::format("{}", m_body.size())}});
    for (const auto& [name, value] : m_headers)
    {
        head.AddField(HeaderField{name, value});
    }
    return head.Encode() + m_body;
}

} // namespace tailgate::net::http
