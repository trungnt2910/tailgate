#include "tailgate/net/http/Message.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <set>
#include <string_view>

namespace tailgate::net::http
{

MessageError::MessageError(MessageErrorKind kind) noexcept : m_kind(kind)
{
}

MessageErrorKind MessageError::Kind() const noexcept
{
    return m_kind;
}

const char* MessageError::what() const noexcept
{
    switch (m_kind)
    {
    case MessageErrorKind::Malformed:
        return "malformed HTTP message";
    case MessageErrorKind::HeaderLimit:
        return "HTTP header limit exceeded";
    case MessageErrorKind::BodyLimit:
        return "HTTP body limit exceeded";
    case MessageErrorKind::Truncated:
        return "truncated HTTP message";
    case MessageErrorKind::InvalidState:
        return "invalid HTTP codec state";
    }
    return "HTTP message error";
}

namespace
{

char Lower(char character) noexcept
{
    return static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
}

std::string Lower(std::string_view text)
{
    std::string result(text);
    std::ranges::transform(result,
                           result.begin(),
                           [](char character)
                           {
                               return Lower(character);
                           });
    return result;
}

} // namespace

bool HeaderField::EqualText(std::string_view left, std::string_view right) noexcept
{
    return left.size() == right.size() && std::equal(left.begin(),
                                                     left.end(),
                                                     right.begin(),
                                                     [](char a, char b)
                                                     {
                                                         return Lower(a) == Lower(b);
                                                     });
}

std::optional<std::string_view> MessageHead::SingleField(std::string_view name) const
{
    std::optional<std::string_view> result;
    for (const auto& field : m_fields)
    {
        if (HeaderField::EqualText(field.Name(), name))
        {
            if (result)
            {
                throw MessageError(MessageErrorKind::Malformed);
            }
            result = field.Value();
        }
    }
    return result;
}

void MessageHead::RemoveField(std::string_view name)
{
    std::erase_if(m_fields,
                  [&](const auto& field)
                  {
                      return HeaderField::EqualText(field.Name(), name);
                  });
}

void MessageHead::RemoveHopByHopFields()
{
    std::set<std::string> names{"connection",
                                "keep-alive",
                                "proxy-authenticate",
                                "proxy-authorization",
                                "proxy-connection",
                                "te",
                                "trailer",
                                "transfer-encoding",
                                "upgrade"};
    for (const auto& field : m_fields)
    {
        if (!HeaderField::EqualText(field.Name(), "Connection"))
        {
            continue;
        }
        std::string_view remaining(field.Value());
        while (!remaining.empty())
        {
            const auto comma = remaining.find(',');
            auto token = remaining.substr(0, comma);
            const auto first = token.find_first_not_of(" \t");
            const auto last = token.find_last_not_of(" \t");
            if (first != std::string_view::npos)
            {
                names.insert(Lower(token.substr(first, last - first + 1)));
            }
            if (comma == std::string_view::npos)
            {
                break;
            }
            remaining.remove_prefix(comma + 1);
        }
    }
    std::erase_if(m_fields,
                  [&](const auto& field)
                  {
                      return names.contains(Lower(field.Name()));
                  });
}

void MessageHead::ValidateFraming() const
{
    bool lengthSeen = false;
    bool transferSeen = false;
    for (const auto& field : m_fields)
    {
        if (HeaderField::EqualText(field.Name(), "Content-Length"))
        {
            std::uint64_t length = 0;
            const auto [end, error] = std::from_chars(
                field.Value().data(), field.Value().data() + field.Value().size(), length);
            if (lengthSeen || transferSeen || field.Value().empty() || error != std::errc{} ||
                end != field.Value().data() + field.Value().size())
            {
                throw MessageError(MessageErrorKind::Malformed);
            }
            lengthSeen = true;
        }
        if (HeaderField::EqualText(field.Name(), "Transfer-Encoding"))
        {
            // The body decoder removes chunk framing only; forwarding any other transport
            // coding as decoded file bytes would silently corrupt uploads or downloads.
            if (lengthSeen || transferSeen || !HeaderField::EqualText(field.Value(), "chunked"))
            {
                throw MessageError(MessageErrorKind::Malformed);
            }
            transferSeen = true;
        }
    }
}

void HeaderField::ValidateTrailer() const
{
    constexpr std::string_view Forbidden[] = {"Content-Length",
                                              "Transfer-Encoding",
                                              "Host",
                                              "Connection",
                                              "Trailer",
                                              "TE",
                                              "Upgrade",
                                              "Authorization",
                                              "Proxy-Authorization",
                                              "Content-Type",
                                              "Content-Encoding",
                                              "Content-Range",
                                              "Content-Location",
                                              "Location",
                                              "WWW-Authenticate",
                                              "Proxy-Authenticate",
                                              "Cookie",
                                              "Set-Cookie"};
    if (std::ranges::any_of(Forbidden,
                            [this](auto name)
                            {
                                return HasName(name);
                            }))
    {
        throw MessageError(MessageErrorKind::Malformed);
    }
}

bool HeaderField::HasName(std::string_view name) const noexcept
{
    return EqualText(m_name, name);
}

} // namespace tailgate::net::http
