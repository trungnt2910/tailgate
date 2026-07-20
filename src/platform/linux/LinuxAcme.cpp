#include "LinuxAcme.h"
#include "LinuxCaBundle.h"
#include "LinuxFiles.h"
#include "TcpStream.h"
#include "tailgate/protocol/TlsStream.h"
#include <charconv>
#include <format>
#include <stdexcept>
#include <thread>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>

namespace tailgate::linux_frontend
{
namespace
{

struct Endpoint
{
    std::string Host, Port, Path;
};

Endpoint Parse(const std::string& url)
{
    constexpr std::string_view prefix = "https://";
    if (!url.starts_with(prefix))
    {
        throw std::runtime_error("ACME URL is not HTTPS: " + url);
    }
    const std::size_t slash = url.find('/', prefix.size());
    const std::string authority = url.substr(prefix.size(), slash - prefix.size());
    const std::size_t colon = authority.rfind(':');
    return Endpoint{.Host = colon == std::string::npos ? authority : authority.substr(0, colon),
                    .Port = colon == std::string::npos ? "443" : authority.substr(colon + 1),
                    .Path = slash == std::string::npos ? "/" : url.substr(slash)};
}

std::string Lower(std::string text)
{
    boost::algorithm::to_lower(text);
    return text;
}

std::vector<std::uint8_t> Bytes(const std::string& text)
{
    return {text.begin(), text.end()};
}

std::size_t ParseHexSize(std::string text)
{
    if (text.empty() || text.size() > sizeof(std::size_t) * 2)
    {
        throw std::runtime_error("invalid ACME response chunk size");
    }
    if (text.size() % 2 != 0)
    {
        text.insert(text.begin(), '0');
    }
    std::vector<std::uint8_t> bytes;
    try
    {
        boost::algorithm::unhex(text, std::back_inserter(bytes));
    }
    catch (const boost::algorithm::hex_decode_error&)
    {
        throw std::runtime_error("invalid ACME response chunk size");
    }
    std::size_t result = 0;
    for (const std::uint8_t byte : bytes)
    {
        result = (result << 8U) | byte;
    }
    return result;
}

std::string DecodeChunked(const std::string& body)
{
    std::string decoded;
    std::size_t offset = 0;
    while (true)
    {
        const std::size_t lineEnd = body.find("\r\n", offset);
        if (lineEnd == std::string::npos)
        {
            throw std::runtime_error("truncated chunked ACME response");
        }
        const std::size_t extension = body.find(';', offset);
        const std::size_t numberEnd = extension < lineEnd ? extension : lineEnd;
        const std::size_t size = ParseHexSize(body.substr(offset, numberEnd - offset));
        offset = lineEnd + 2;
        if (size == 0)
        {
            return decoded;
        }
        if (size > body.size() - offset || body.size() - offset - size < 2)
        {
            throw std::runtime_error("truncated ACME response chunk");
        }
        decoded.append(body, offset, size);
        offset += size;
        if (body.compare(offset, 2, "\r\n") != 0)
        {
            throw std::runtime_error("invalid ACME response chunk delimiter");
        }
        offset += 2;
    }
}

} // namespace

acme::HttpResponse LinuxAcmeHttpClient::Send(const acme::HttpRequest& request)
{
    const Endpoint endpoint = Parse(request.Url);
    TcpStream socket(endpoint.Host, endpoint.Port, {}, TcpStream::ControlIoTimeoutSeconds);
    protocol::TlsStream tls(socket, endpoint.Host, SystemCaBundle());
    std::string output = std::format("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n"
                                     "Content-Length: {}\r\n",
                                     request.Method,
                                     endpoint.Path,
                                     endpoint.Host,
                                     request.Body.size());
    for (const auto& [name, value] : request.Headers)
    {
        output += std::format("{}: {}\r\n", name, value);
    }
    output += std::format("\r\n{}", request.Body);
    tls.WriteAll(Bytes(output));
    std::string response;
    while (true)
    {
        auto part = tls.ReadSome(16U * 1024U);
        if (part.empty())
        {
            break;
        }
        response.append(reinterpret_cast<const char*>(part.data()), part.size());
    }
    const std::size_t headerEnd = response.find("\r\n\r\n");
    if (headerEnd == std::string::npos)
    {
        throw std::runtime_error("ACME HTTP response has no headers");
    }
    acme::HttpResponse result;
    std::vector<std::string> lines;
    boost::algorithm::split(
        lines, response.substr(0, headerEnd), boost::algorithm::is_any_of("\n"));
    std::vector<std::string> statusFields;
    if (!lines.empty())
    {
        boost::algorithm::split(statusFields,
                                lines.front(),
                                boost::algorithm::is_any_of(" \r"),
                                boost::algorithm::token_compress_on);
    }
    if (statusFields.size() < 2)
    {
        throw std::runtime_error("invalid ACME HTTP status line");
    }
    const auto [statusEnd, statusError] = std::from_chars(
        statusFields[1].data(), statusFields[1].data() + statusFields[1].size(), result.Status);
    if (statusError != std::errc{} || statusEnd != statusFields[1].data() + statusFields[1].size())
    {
        throw std::runtime_error("invalid ACME HTTP status code");
    }
    for (auto line = lines.begin() + 1; line != lines.end(); ++line)
    {
        boost::algorithm::trim_right_if(*line, boost::algorithm::is_any_of("\r"));
        const std::size_t colon = line->find(':');
        if (colon != std::string::npos)
        {
            result.Headers[Lower(line->substr(0, colon))] =
                boost::algorithm::trim_left_copy(line->substr(colon + 1));
        }
    }
    result.Body = response.substr(headerEnd + 4);
    const auto transferEncoding = result.Headers.find("transfer-encoding");
    if (transferEncoding != result.Headers.end() &&
        Lower(transferEncoding->second).find("chunked") != std::string::npos)
    {
        result.Body = DecodeChunked(result.Body);
    }
    return result;
}

void LinuxAcmeWaiter::Wait(std::chrono::seconds duration)
{
    std::this_thread::sleep_for(duration);
}

} // namespace tailgate::linux_frontend
