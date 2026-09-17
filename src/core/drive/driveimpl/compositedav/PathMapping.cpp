#include "tailgate/drive/driveimpl/compositedav/Path.h"

#include <algorithm>
#include <cctype>

#include <boost/url/parse.hpp>
#include <boost/url/url.hpp>

#include <tailgate/drive/driveimpl/compositedav/IfHeader.h>

namespace tailgate::drive::driveimpl::compositedav
{
namespace
{

std::string Lower(std::string_view value)
{
    std::string result(value);
    for (auto& character : result)
    {
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    }
    return result;
}

Path Resource(std::string_view reference, const std::vector<std::string>& authorities)
{
    const auto url = boost::urls::parse_uri_reference(reference);
    if (!url || url->has_fragment() || url->has_query())
    {
        throw PathError(PathErrorKind::InvalidPath);
    }
    if (url->has_authority() || url->has_scheme())
    {
        const auto authority = Lower(url->encoded_authority());
        if (Lower(url->scheme()) != "http" || !url->has_authority() || url->has_userinfo() ||
            !std::ranges::any_of(authorities,
                                 [&](const auto& allowed)
                                 {
                                     return !allowed.empty() && authority == Lower(allowed);
                                 }))
        {
            throw PathError(PathErrorKind::InvalidAuthority);
        }
    }
    return Path::Parse(url->encoded_path());
}

std::string LocalPath(const PathMapping& mapping, const Path& path)
{
    std::vector<std::string> segments{mapping.Domain, mapping.RemoteName};
    segments.insert(segments.end(), path.Segments().begin(), path.Segments().end());
    return Path::FromSegments(std::move(segments), path.TrailingSlash()).Encode();
}

} // namespace

std::string PathMapping::ToPeerRequest(std::string_view localPath) const
{
    // The HTTP request target is origin-form, not a user-selected URL to be dialed.
    (void)Path::Parse(localPath);
    return "/v0/drive" + ToPeerResource(localPath);
}

std::string PathMapping::ToPeerResource(std::string_view localReference) const
{
    const auto path = Resource(localReference, LocalAuthorities);
    const auto& segments = path.Segments();
    if (segments.size() < 2 || segments[0] != Domain || segments[1] != RemoteName)
    {
        throw PathError(PathErrorKind::CrossRemote);
    }
    return Path::FromSegments(std::vector<std::string>(segments.begin() + 2, segments.end()),
                              path.TrailingSlash())
        .Encode();
}

std::string PathMapping::ToLocalResource(std::string_view peerReference) const
{
    return LocalPath(*this, Resource(peerReference, {PeerAuthority}));
}

std::string PathMapping::ToLocalLockRoot(std::string_view decodedPeerPath) const
{
    // The Tailscale exporter XML-escapes URL.Path for lockroot, without URI encoding it.
    // In particular, a literal %2F belongs to the filename and must not become a separator.
    if (!decodedPeerPath.starts_with('/') || decodedPeerPath.starts_with("//"))
    {
        throw PathError(PathErrorKind::InvalidPath);
    }
    boost::urls::url url;
    url.set_path(decodedPeerPath);
    return LocalPath(*this, Path::Parse(url.encoded_path()));
}

std::string PathMapping::RewriteIf(std::string_view condition) const
{
    return IfHeader::Parse(condition).Rewrite(*this);
}

} // namespace tailgate::drive::driveimpl::compositedav
