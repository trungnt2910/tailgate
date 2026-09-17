#include "tailgate/drive/driveimpl/compositedav/XmlRewriter.h"

namespace tailgate::drive::driveimpl::compositedav
{

XmlError::XmlError(XmlErrorKind kind) noexcept : m_kind(kind)
{
}

XmlErrorKind XmlError::Kind() const noexcept
{
    return m_kind;
}

const char* XmlError::what() const noexcept
{
    switch (m_kind)
    {
    case XmlErrorKind::Malformed:
        return "malformed WebDAV XML";
    case XmlErrorKind::ForbiddenMarkup:
        return "forbidden WebDAV XML markup";
    case XmlErrorKind::Limit:
        return "WebDAV XML limit exceeded";
    case XmlErrorKind::InvalidState:
        return "invalid WebDAV XML parser state";
    }
    return "WebDAV XML error";
}

XmlRewriter::~XmlRewriter() = default;
XmlRewriterFactory::~XmlRewriterFactory() = default;

std::string EscapeXml(std::string_view text)
{
    std::string result;
    for (const auto character : text)
    {
        switch (character)
        {
        case '&':
            result += "&amp;";
            break;
        case '<':
            result += "&lt;";
            break;
        case '>':
            result += "&gt;";
            break;
        case '"':
            result += "&quot;";
            break;
        case '\'':
            result += "&apos;";
            break;
        case '\r':
            result += "&#13;";
            break;
        case '\n':
            result += "&#10;";
            break;
        case '\t':
            result += "&#9;";
            break;
        default:
            result += character;
            break;
        }
    }
    return result;
}

} // namespace tailgate::drive::driveimpl::compositedav
