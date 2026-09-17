#pragma once

#include <exception>
#include <string>
#include <string_view>
#include <vector>

namespace tailgate::drive::driveimpl::compositedav
{

enum class PathErrorKind
{
    InvalidPath,
    InvalidAuthority,
    CrossRemote,
    InvalidCondition,
};

class PathError final : public std::exception
{
public:
    explicit PathError(PathErrorKind kind) noexcept;
    [[nodiscard]] PathErrorKind Kind() const noexcept;
    [[nodiscard]] const char* what() const noexcept override;

private:
    PathErrorKind m_kind;
};

class Path final
{
public:
    [[nodiscard]] static Path Parse(std::string_view encoded);
    [[nodiscard]] static Path FromSegments(std::vector<std::string> segments,
                                           bool trailingSlash = false);
    [[nodiscard]] const std::vector<std::string>& Segments() const noexcept;
    [[nodiscard]] bool TrailingSlash() const noexcept;
    [[nodiscard]] std::string Encode() const;

private:
    std::vector<std::string> m_segments;
    bool m_trailingSlash = false;
};

// Immutable mapping for one exchange. Authorities are service aliases or the selected netmap
// PeerAPI endpoint, never values supplied by Destination or an upstream XML response.
struct PathMapping
{
    std::string Domain;
    std::string RemoteName;
    std::vector<std::string> LocalAuthorities;
    std::string PeerAuthority;

    [[nodiscard]] std::string ToPeerRequest(std::string_view localPath) const;
    [[nodiscard]] std::string ToPeerResource(std::string_view localReference) const;
    [[nodiscard]] std::string ToLocalResource(std::string_view peerReference) const;
    [[nodiscard]] std::string ToLocalLockRoot(std::string_view decodedPeerPath) const;
    [[nodiscard]] std::string RewriteIf(std::string_view condition) const;
};

} // namespace tailgate::drive::driveimpl::compositedav
