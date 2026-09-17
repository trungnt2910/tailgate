#include <string>

#include <gtest/gtest.h>

#include <tailgate/drive/driveimpl/compositedav/Path.h>

namespace tailgate::tests
{
namespace dav = drive::driveimpl::compositedav;

class Given_DavPath : public testing::TestWithParam<const char*>
{
protected:
    const dav::PathMapping m_mapping{
        .Domain = "example.ts.net",
        .RemoteName = "laptop",
        .LocalAuthorities = {"100.100.100.100:8080", "dav.example.com:8080"},
        .PeerAuthority = "100.64.0.2:12345"};
};

TEST_F(Given_DavPath, When_LocalResourceIsForwarded_Then_RequestUsesPeerApiPrefix)
{
    const std::string local = "/example.ts.net/laptop/docs/a%20b";

    const auto request = m_mapping.ToPeerRequest(local);
    const auto resource = m_mapping.ToPeerResource(local);

    EXPECT_EQ(request, "/v0/drive/docs/a%20b");
    EXPECT_EQ(resource, "/docs/a%20b");
}

TEST_F(Given_DavPath, When_PeerHrefIsRewritten_Then_LocalTreePrefixIsAdded)
{
    const std::string href = "/docs/folder/";

    const auto local = m_mapping.ToLocalResource(href);

    EXPECT_EQ(local, "/example.ts.net/laptop/docs/folder/");
}

TEST_F(Given_DavPath, When_AbsoluteDestinationUsesServiceAuthority_Then_AuthorityIsRemoved)
{
    const std::string destination = "http://dav.example.com:8080/example.ts.net/laptop/docs/b";

    const auto resource = m_mapping.ToPeerResource(destination);

    EXPECT_EQ(resource, "/docs/b");
}

TEST_F(Given_DavPath, When_LockRootContainsLiteralEscapes_Then_EscapesRemainFilenameCharacters)
{
    const std::string path = "/docs/%2e%2e/%2F 雪#?/";

    const auto local = m_mapping.ToLocalLockRoot(path);

    EXPECT_EQ(local, "/example.ts.net/laptop/docs/%252e%252e/%252F%20%E9%9B%AA%23%3F/");
}

TEST_F(Given_DavPath, When_LockRootIsRoot_Then_LocalRemoteRootIsReturned)
{
    const std::string path = "/";

    const auto local = m_mapping.ToLocalLockRoot(path);

    EXPECT_EQ(local, "/example.ts.net/laptop/");
}

TEST_F(Given_DavPath, When_LockRootContainsTraversal_Then_ResponseIsRejected)
{
    const std::string path = "/docs/../other";

    EXPECT_THROW((void)m_mapping.ToLocalLockRoot(path), dav::PathError);
}

TEST_F(Given_DavPath, When_LockRootContainsAuthority_Then_ResponseIsRejected)
{
    const std::string path = "//other.example.com/docs/file";

    EXPECT_THROW((void)m_mapping.ToLocalLockRoot(path), dav::PathError);
}

TEST_F(Given_DavPath, When_LockRootContainsAbsoluteUrl_Then_ResponseIsRejected)
{
    const std::string path = "http://other.example.com/docs/file";

    EXPECT_THROW((void)m_mapping.ToLocalLockRoot(path), dav::PathError);
}

TEST_F(Given_DavPath, When_DestinationUsesUnrelatedAuthority_Then_RequestIsRejected)
{
    const std::string destination = "http://other.example.com/example.ts.net/laptop/docs/b";

    EXPECT_THROW((void)m_mapping.ToPeerResource(destination), dav::PathError);
}

TEST_F(Given_DavPath, When_DestinationNamesAnotherPeer_Then_RequestIsRejected)
{
    const std::string destination = "/example.ts.net/another/docs/b";

    EXPECT_THROW((void)m_mapping.ToPeerResource(destination), dav::PathError);
}

TEST_F(Given_DavPath, When_PeerHrefUsesUnrelatedAuthority_Then_ResponseCannotRedirectTheClient)
{
    const std::string href = "http://other.example.com/docs/a";

    EXPECT_THROW((void)m_mapping.ToLocalResource(href), dav::PathError);
}

TEST_F(Given_DavPath, When_EscapesContainUnicodeAndLiteralPercent_Then_EachIsDecodedOnlyOnce)
{
    const std::string input = "/docs/%e2%98%83/%252e%252e";

    const auto path = dav::Path::Parse(input);
    const auto output = path.Encode();

    EXPECT_EQ(output, "/docs/%E2%98%83/%252e%252e");
    EXPECT_EQ(path.Segments().back(), "%2e%2e");
}

TEST_F(Given_DavPath, When_RootIsParsed_Then_ItHasNoSegments)
{
    const std::string input = "/";

    const auto path = dav::Path::Parse(input);

    EXPECT_TRUE(path.Segments().empty());
    EXPECT_EQ(path.Encode(), "/");
}

TEST_P(Given_DavPath, When_PathHasAmbiguousOrInvalidSyntax_Then_ItIsRejected)
{
    const std::string path = GetParam();

    EXPECT_THROW((void)dav::Path::Parse(path), dav::PathError);
}

INSTANTIATE_TEST_SUITE_P(Paths,
                         Given_DavPath,
                         testing::Values("/docs/../a",
                                         "/docs/%2e%2e/a",
                                         "/docs/a%2fb",
                                         "/docs/a%5cb",
                                         "/docs/a%00b",
                                         "/docs//a",
                                         "/docs/%",
                                         "/docs/a?query",
                                         "/docs/a#fragment",
                                         "docs/a"));

} // namespace tailgate::tests
