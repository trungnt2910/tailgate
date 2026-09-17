#include "tailgate/drive/driveimpl/compositedav/Path.h"

#include <algorithm>

#include <boost/url/encode.hpp>
#include <boost/url/parse.hpp>
#include <boost/url/rfc/unreserved_chars.hpp>

namespace tailgate::drive::driveimpl::compositedav
{
namespace
{

constexpr std::size_t MaximumPathBytes = 16U * 1024U;
constexpr std::size_t MaximumPathSegments = 128;

bool ValidSegment(std::string_view segment)
{
    return !segment.empty() && segment != "." && segment != ".." &&
           std::ranges::all_of(segment,
                               [](unsigned char character)
                               {
                                   return character >= ' ' && character != 127 &&
                                          character != '/' && character != '\\';
                               });
}

} // namespace

PathError::PathError(PathErrorKind kind) noexcept : m_kind(kind)
{
}

PathErrorKind PathError::Kind() const noexcept
{
    return m_kind;
}

const char* PathError::what() const noexcept
{
    switch (m_kind)
    {
    case PathErrorKind::InvalidPath:
        return "invalid WebDAV path";
    case PathErrorKind::InvalidAuthority:
        return "invalid WebDAV authority";
    case PathErrorKind::CrossRemote:
        return "WebDAV resource belongs to another remote";
    case PathErrorKind::InvalidCondition:
        return "invalid WebDAV If condition";
    }
    return "WebDAV path error";
}

Path Path::Parse(std::string_view encoded)
{
    const auto url = boost::urls::parse_origin_form(encoded);
    if (encoded.size() > MaximumPathBytes || !url || url->has_query())
    {
        throw PathError(PathErrorKind::InvalidPath);
    }
    std::vector<std::string> segments;
    for (const auto segment : url->segments())
    {
        segments.emplace_back(segment);
    }
    const bool trailingSlash = encoded.ends_with('/');
    if (trailingSlash && !segments.empty() && segments.back().empty())
    {
        segments.pop_back();
    }
    return FromSegments(std::move(segments), trailingSlash);
}

Path Path::FromSegments(std::vector<std::string> segments, bool trailingSlash)
{
    if (segments.size() > MaximumPathSegments || !std::ranges::all_of(segments, ValidSegment))
    {
        throw PathError(PathErrorKind::InvalidPath);
    }
    Path result;
    result.m_segments = std::move(segments);
    result.m_trailingSlash = trailingSlash;
    if (result.Encode().size() > MaximumPathBytes)
    {
        throw PathError(PathErrorKind::InvalidPath);
    }
    return result;
}

const std::vector<std::string>& Path::Segments() const noexcept
{
    return m_segments;
}

bool Path::TrailingSlash() const noexcept
{
    return m_trailingSlash;
}

std::string Path::Encode() const
{
    std::string result;
    for (const auto& segment : m_segments)
    {
        result += '/';
        result += boost::urls::encode(segment, boost::urls::unreserved_chars);
    }
    if (m_trailingSlash || result.empty())
    {
        result += '/';
    }
    return result;
}

} // namespace tailgate::drive::driveimpl::compositedav
