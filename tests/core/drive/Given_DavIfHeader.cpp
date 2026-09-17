#include <gtest/gtest.h>

#include <tailgate/drive/driveimpl/compositedav/IfHeader.h>

namespace tailgate::tests
{
namespace dav = drive::driveimpl::compositedav;

class Given_DavIfHeader : public testing::TestWithParam<const char*>
{
protected:
    const dav::PathMapping m_mapping{.Domain = "example.ts.net",
                                     .RemoteName = "laptop",
                                     .LocalAuthorities = {"100.100.100.100:8080"},
                                     .PeerAuthority = "100.64.0.2:12345"};
};

TEST_F(Given_DavIfHeader, When_ResourceIsTagged_Then_OnlyResourceHrefIsRewritten)
{
    const std::string input = "<http://100.100.100.100:8080/example.ts.net/laptop/docs/a> "
                              "(<opaquelocktoken:example-lock> [\"etag\"])";

    const auto output = dav::IfHeader::Parse(input).Rewrite(m_mapping);

    EXPECT_EQ(output, "</docs/a> (<opaquelocktoken:example-lock> [\"etag\"])");
}

TEST_F(Given_DavIfHeader, When_NoResourceIsTagged_Then_LockTokensAndWeakEtagsRemainUnchanged)
{
    const std::string input =
        "(Not <opaquelocktoken:first>) (<opaquelocktoken:second> [W/\"etag\"])";

    const auto output = dav::IfHeader::Parse(input).Rewrite(m_mapping);

    EXPECT_EQ(output, input);
}

TEST_F(Given_DavIfHeader, When_MultipleResourcesAreTagged_Then_AllResourceHrefsAreRewritten)
{
    const std::string input = "</example.ts.net/laptop/docs/a> (<opaquelocktoken:first>) "
                              "</example.ts.net/laptop/docs/b> ([\"etag\"])";

    const auto output = dav::IfHeader::Parse(input).Rewrite(m_mapping);

    EXPECT_EQ(output, "</docs/a> (<opaquelocktoken:first>) </docs/b> ([\"etag\"])");
}

TEST_F(Given_DavIfHeader, When_StateTokenLooksLikeResourceUrl_Then_ItRemainsOpaque)
{
    const std::string input = "(<http://100.100.100.100:8080/example.ts.net/laptop/docs/a>)";

    const auto output = dav::IfHeader::Parse(input).Rewrite(m_mapping);

    EXPECT_EQ(output, input);
}

TEST_P(Given_DavIfHeader, When_ConditionalHeaderIsInvalid_Then_ItIsRejected)
{
    const std::string input = GetParam();

    EXPECT_THROW((void)dav::IfHeader::Parse(input).Rewrite(m_mapping), dav::PathError);
}

INSTANTIATE_TEST_SUITE_P(
    Conditions,
    Given_DavIfHeader,
    testing::Values("()",
                    "(<opaquelocktoken:example>",
                    "<http://example.com/no-list>",
                    "(Not<opaquelocktoken:example>)",
                    "([etag])",
                    "( [\"unterminated])",
                    "</example.ts.net/another/docs/a> (<opaquelocktoken:example>)"));

} // namespace tailgate::tests
