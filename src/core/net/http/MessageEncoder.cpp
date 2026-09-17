#include "tailgate/net/http/Message.h"

#include <algorithm>
#include <format>
#include <string_view>

namespace tailgate::net::http
{
namespace
{

bool Token(std::string_view text)
{
    constexpr std::string_view Punctuation = "!#$%&'*+-.^_`|~";
    return !text.empty() &&
           std::ranges::all_of(text,
                               [&](unsigned char character)
                               {
                                   return (character >= '0' && character <= '9') ||
                                          (character >= 'A' && character <= 'Z') ||
                                          (character >= 'a' && character <= 'z') ||
                                          Punctuation.find(character) != std::string_view::npos;
                               });
}

bool FieldValue(std::string_view text)
{
    return std::ranges::all_of(text,
                               [](unsigned char character)
                               {
                                   return character == '\t' ||
                                          (character >= ' ' && character != '\x7f');
                               });
}

void AppendFields(std::string& output, const std::vector<HeaderField>& fields)
{
    for (const auto& field : fields)
    {
        if (!Token(field.Name()) || !FieldValue(field.Value()))
        {
            throw MessageError(MessageErrorKind::Malformed);
        }
        output += std::format("{}: {}\r\n", field.Name(), field.Value());
    }
    output += "\r\n";
}

std::string_view ReasonPhrase(unsigned status)
{
    switch (status)
    {
    case 100:
        return "Continue";
    case 101:
        return "Switching Protocols";
    case 102:
        return "Processing";
    case 103:
        return "Early Hints";
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 202:
        return "Accepted";
    case 203:
        return "Non-Authoritative Information";
    case 204:
        return "No Content";
    case 205:
        return "Reset Content";
    case 206:
        return "Partial Content";
    case 207:
        return "Multi-Status";
    case 208:
        return "Already Reported";
    case 226:
        return "IM Used";
    case 300:
        return "Multiple Choices";
    case 301:
        return "Moved Permanently";
    case 302:
        return "Found";
    case 303:
        return "See Other";
    case 304:
        return "Not Modified";
    case 305:
        return "Use Proxy";
    case 307:
        return "Temporary Redirect";
    case 308:
        return "Permanent Redirect";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 402:
        return "Payment Required";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 406:
        return "Not Acceptable";
    case 407:
        return "Proxy Authentication Required";
    case 408:
        return "Request Timeout";
    case 409:
        return "Conflict";
    case 410:
        return "Gone";
    case 411:
        return "Length Required";
    case 412:
        return "Precondition Failed";
    case 413:
        return "Payload Too Large";
    case 414:
        return "URI Too Long";
    case 415:
        return "Unsupported Media Type";
    case 416:
        return "Range Not Satisfiable";
    case 417:
        return "Expectation Failed";
    case 418:
        return "I'm a teapot";
    case 421:
        return "Misdirected Request";
    case 422:
        return "Unprocessable Entity";
    case 423:
        return "Locked";
    case 424:
        return "Failed Dependency";
    case 425:
        return "Too Early";
    case 426:
        return "Upgrade Required";
    case 428:
        return "Precondition Required";
    case 429:
        return "Too Many Requests";
    case 431:
        return "Request Header Fields Too Large";
    case 451:
        return "Unavailable For Legal Reasons";
    case 500:
        return "Internal Server Error";
    case 501:
        return "Not Implemented";
    case 502:
        return "Bad Gateway";
    case 503:
        return "Service Unavailable";
    case 504:
        return "Gateway Timeout";
    case 505:
        return "HTTP Version Not Supported";
    case 506:
        return "Variant Also Negotiates";
    case 507:
        return "Insufficient Storage";
    case 508:
        return "Loop Detected";
    case 510:
        return "Not Extended";
    case 511:
        return "Network Authentication Required";
    default:
        return "Unknown Status";
    }
}

} // namespace

std::string MessageHead::Encode() const
{
    ValidateFraming();
    if (Version() != 10 && Version() != 11)
    {
        throw MessageError(MessageErrorKind::Malformed);
    }
    std::string result;
    if (Kind() == MessageKind::Request)
    {
        if (!Token(Method()) || Target().empty() ||
            !std::ranges::all_of(Target(),
                                 [](unsigned char character)
                                 {
                                     return character > ' ' && character != '\x7f';
                                 }))
        {
            throw MessageError(MessageErrorKind::Malformed);
        }
        result = std::format("{} {} HTTP/1.{}\r\n", Method(), Target(), Version() % 10);
    }
    else
    {
        if (Status() < 100 || Status() > 599 || !FieldValue(Reason()))
        {
            throw MessageError(MessageErrorKind::Malformed);
        }
        result = std::format("HTTP/1.{} {} {}\r\n",
                             Version() % 10,
                             Status(),
                             Reason().empty() ? ReasonPhrase(Status()) : Reason());
    }
    AppendFields(result, Fields());
    return result;
}

std::string ChunkEncoder::Encode(std::span<const std::uint8_t> body)
{
    if (body.empty())
    {
        // Only EncodeLast may terminate a chunked message.
        return {};
    }
    auto result = std::format("{:x}\r\n", body.size());
    result.append(reinterpret_cast<const char*>(body.data()), body.size());
    result += "\r\n";
    return result;
}

std::string ChunkEncoder::EncodeLast(const std::vector<HeaderField>& trailers)
{
    for (const auto& field : trailers)
    {
        field.ValidateTrailer();
    }
    std::string result = "0\r\n";
    AppendFields(result, trailers);
    return result;
}

} // namespace tailgate::net::http
