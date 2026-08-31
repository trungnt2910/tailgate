#include "tailgate/net/http/Client.h"

#include <algorithm>
#include <cctype>
#include <charconv>
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
    case CodecErrorKind::MissingHeaders:
        return "HTTP response has no headers";
    case CodecErrorKind::InvalidStatusLine:
        return "HTTP response status line is invalid";
    case CodecErrorKind::InvalidStatusCode:
        return "HTTP response status code is invalid";
    case CodecErrorKind::InvalidChunkSize:
        return "HTTP response chunk size is invalid";
    case CodecErrorKind::TruncatedChunk:
        return "HTTP response chunk is truncated";
    case CodecErrorKind::InvalidChunkDelimiter:
        return "HTTP response chunk delimiter is invalid";
    }
    return "HTTP codec failed";
}

std::string Lower(std::string text)
{
    std::ranges::transform(text,
                           text.begin(),
                           [](unsigned char value)
                           {
                               return static_cast<char>(std::tolower(value));
                           });
    return text;
}

std::string Trim(std::string text)
{
    const std::size_t begin = text.find_first_not_of(" \t\r");
    if (begin == std::string::npos)
    {
        return {};
    }
    const std::size_t end = text.find_last_not_of(" \t\r");
    return text.substr(begin, end - begin + 1);
}

std::string DecodeChunked(const std::string& encoded)
{
    std::string result;
    std::size_t offset = 0;
    while (true)
    {
        const std::size_t lineEnd = encoded.find("\r\n", offset);
        if (lineEnd == std::string::npos)
        {
            throw CodecError(CodecErrorKind::TruncatedChunk);
        }
        const std::size_t extension = encoded.find(';', offset);
        const std::size_t numberEnd = extension < lineEnd ? extension : lineEnd;
        const std::string_view sizeText(encoded.data() + offset, numberEnd - offset);
        std::size_t size = 0;
        const auto [end, error] =
            std::from_chars(sizeText.data(), sizeText.data() + sizeText.size(), size, 16);
        if (sizeText.empty() || error != std::errc{} || end != sizeText.data() + sizeText.size())
        {
            throw CodecError(CodecErrorKind::InvalidChunkSize);
        }
        offset = lineEnd + 2;
        if (size == 0)
        {
            return result;
        }
        if (size > encoded.size() - offset || encoded.size() - offset - size < 2)
        {
            throw CodecError(CodecErrorKind::TruncatedChunk);
        }
        result.append(encoded, offset, size);
        offset += size;
        if (encoded.compare(offset, 2, "\r\n") != 0)
        {
            throw CodecError(CodecErrorKind::InvalidChunkDelimiter);
        }
        offset += 2;
    }
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
    std::string result = std::format("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n"
                                     "Content-Length: {}\r\n",
                                     m_method,
                                     url.Path(),
                                     url.Host(),
                                     m_body.size());
    for (const auto& [name, value] : m_headers)
    {
        result += std::format("{}: {}\r\n", name, value);
    }
    return result + std::format("\r\n{}", m_body);
}

Response Response::Decode(const std::string& encoded)
{
    const std::size_t headerEnd = encoded.find("\r\n\r\n");
    if (headerEnd == std::string::npos)
    {
        throw CodecError(CodecErrorKind::MissingHeaders);
    }
    const std::size_t statusEnd = encoded.find("\r\n");
    const std::size_t firstSpace = encoded.find(' ');
    if (statusEnd == std::string::npos || firstSpace == std::string::npos ||
        firstSpace >= statusEnd)
    {
        throw CodecError(CodecErrorKind::InvalidStatusLine);
    }
    const std::size_t secondSpace = encoded.find(' ', firstSpace + 1);
    const std::size_t codeEnd = secondSpace < statusEnd ? secondSpace : statusEnd;
    int status = 0;
    const auto [parsedEnd, statusError] =
        std::from_chars(encoded.data() + firstSpace + 1, encoded.data() + codeEnd, status);
    if (statusError != std::errc{} || parsedEnd != encoded.data() + codeEnd)
    {
        throw CodecError(CodecErrorKind::InvalidStatusCode);
    }
    std::map<std::string, std::string> headers;
    std::size_t line = statusEnd + 2;
    while (line < headerEnd)
    {
        const std::size_t lineEnd = encoded.find("\r\n", line);
        const std::size_t colon = encoded.find(':', line);
        if (colon < lineEnd && lineEnd <= headerEnd)
        {
            headers[Lower(encoded.substr(line, colon - line))] =
                Trim(encoded.substr(colon + 1, lineEnd - colon - 1));
        }
        line = lineEnd + 2;
    }
    std::string body = encoded.substr(headerEnd + 4);
    const auto transferEncoding = headers.find("transfer-encoding");
    if (transferEncoding != headers.end() &&
        Lower(transferEncoding->second).find("chunked") != std::string::npos)
    {
        body = DecodeChunked(body);
    }
    return Response(status, std::move(headers), std::move(body));
}

} // namespace tailgate::net::http
