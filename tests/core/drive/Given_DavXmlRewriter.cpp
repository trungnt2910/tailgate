#include <algorithm>
#include <span>
#include <string>

#include <gtest/gtest.h>

#include <tailgate/di/Bindings.h>
#include <tailgate/drive/driveimpl/compositedav/XmlRewriter.h>

#include "fakes/di/FakeNetworkBindings.h"

namespace tailgate::tests
{
namespace dav = drive::driveimpl::compositedav;

class Given_DavXmlRewriter : public testing::Test
{
protected:
    Given_DavXmlRewriter()
    {
        fakes::InstallFakeNetworkBindings(injector);
    }

    std::unique_ptr<dav::XmlRewriter> Create()
    {
        return injector.create<dav::XmlRewriterFactory&>().Create(mapping);
    }

    static std::span<const std::uint8_t> Bytes(std::string_view text)
    {
        return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
    }

    di::Injector injector;
    const dav::PathMapping mapping{.Domain = "example.ts.net",
                                   .RemoteName = "laptop",
                                   .LocalAuthorities = {"100.100.100.100:8080"},
                                   .PeerAuthority = "100.64.0.2:12345"};
};

TEST_F(Given_DavXmlRewriter, When_DefaultNamespaceIsUsed_Then_DavResponseHrefIsRewritten)
{
    auto rewriter = Create();
    const std::string input = "<multistatus xmlns=\"DAV:\"><response>"
                              "<href>/docs/a%20b</href></response></multistatus>";

    const auto output = rewriter->Transform(Bytes(input), true);

    EXPECT_NE(output.find("<href>/example.ts.net/laptop/docs/a%20b</href>"), std::string::npos);
    EXPECT_NE(output.find("xmlns=\"DAV:\""), std::string::npos);
}

TEST_F(Given_DavXmlRewriter, When_PrefixDiffersFromOfficialClient_Then_NamespaceControlsRewriting)
{
    auto rewriter = Create();
    const std::string input = "<x:multistatus xmlns:x=\"DAV:\"><x:response>"
                              "<x:href>/docs/a</x:href></x:response></x:multistatus>";

    const auto output = rewriter->Transform(Bytes(input), true);

    EXPECT_NE(output.find("<x:href>/example.ts.net/laptop/docs/a</x:href>"), std::string::npos);
}

TEST_F(Given_DavXmlRewriter, When_LockResponseContainsOwnerAndLockroot_Then_OnlyLockrootIsRewritten)
{
    auto rewriter = Create();
    const std::string input = "<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>"
                              "<D:owner><D:href>http://owner.example.com/</D:href></D:owner>"
                              "<D:locktoken><D:href>opaquelocktoken:example</D:href></D:locktoken>"
                              "<D:lockroot><D:href>/docs/a</D:href></D:lockroot>"
                              "</D:activelock></D:lockdiscovery></D:prop>";

    const auto output = rewriter->Transform(Bytes(input), true);

    EXPECT_NE(output.find("<D:owner><D:href>http://owner.example.com/</D:href>"),
              std::string::npos);
    EXPECT_NE(output.find("<D:locktoken><D:href>opaquelocktoken:example</D:href>"),
              std::string::npos);
    EXPECT_NE(output.find("<D:lockroot><D:href>/example.ts.net/laptop/docs/a</D:href>"),
              std::string::npos);
}

TEST_F(Given_DavXmlRewriter, When_SameLocalNamesUseDifferentNamespace_Then_ContentIsUnchanged)
{
    auto rewriter = Create();
    const std::string input =
        "<response xmlns=\"https://example.com/xml\"><href>/docs/a</href></response>";

    const auto output = rewriter->Transform(Bytes(input), true);

    EXPECT_NE(output.find("<href>/docs/a</href>"), std::string::npos);
    EXPECT_EQ(output.find("example.ts.net/laptop"), std::string::npos);
}

TEST_F(Given_DavXmlRewriter,
       When_LockrootContainsDecodedUnicodeAndPercent_Then_FilenameIsEncodedWithoutDecoding)
{
    auto rewriter = Create();
    const std::string input = "<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>"
                              "<D:lockroot><D:href>/docs/雪 100% %2F#?.txt</D:href></D:lockroot>"
                              "</D:activelock></D:lockdiscovery></D:prop>";

    const auto output = rewriter->Transform(Bytes(input), true);

    EXPECT_NE(output.find("<D:href>/example.ts.net/laptop/docs/"
                          "%E9%9B%AA%20100%25%20%252F%23%3F.txt</D:href>"),
              std::string::npos);
}

TEST_F(Given_DavXmlRewriter, When_XmlArrivesOneByteAtATime_Then_HrefsCrossingChunksAreRewritten)
{
    auto rewriter = Create();
    const std::string input = "<response xmlns=\"DAV:\"><href>/docs/a</href></response>";
    std::string output;

    for (std::size_t index = 0; index < input.size(); ++index)
    {
        output += rewriter->Transform(Bytes(std::string_view(input).substr(index, 1)),
                                      index + 1 == input.size());
    }

    EXPECT_NE(output.find("<href>/example.ts.net/laptop/docs/a</href>"), std::string::npos);
}

TEST_F(Given_DavXmlRewriter, When_DecodedLockRootArrivesBytewise_Then_UnicodeIsEncodedOnce)
{
    auto rewriter = Create();
    const std::string input =
        "<lockroot xmlns=\"DAV:\"><href>/docs/雪 %2F&amp;.txt</href></lockroot>";
    std::string output;

    for (std::size_t index = 0; index < input.size(); ++index)
    {
        output += rewriter->Transform(Bytes(std::string_view(input).substr(index, 1)),
                                      index + 1 == input.size());
    }

    EXPECT_NE(output.find("<href>/example.ts.net/laptop/docs/%E9%9B%AA%20%252F%26.txt</href>"),
              std::string::npos);
}

TEST_F(Given_DavXmlRewriter, When_AttributesContainCharacterReferences_Then_TheirValuesArePreserved)
{
    auto rewriter = Create();
    const std::string input = "<D:prop xmlns:D=\"DAV:\" xmlns:x=\"https://example.com/xml\" "
                              "x:value=\"first&#10;second&amp;third\"/>";

    const auto output = rewriter->Transform(Bytes(input), true);

    EXPECT_NE(output.find("x:value=\"first&#10;second&amp;third\""), std::string::npos);
}

TEST_F(Given_DavXmlRewriter, When_DocumentHasDoctype_Then_NoEntityCanBeLoaded)
{
    auto rewriter = Create();
    const std::string input = "<!DOCTYPE prop SYSTEM \"https://example.com/external.dtd\">"
                              "<prop xmlns=\"DAV:\"/>";

    EXPECT_THROW((void)rewriter->Transform(Bytes(input), true), dav::XmlError);
}

TEST_F(Given_DavXmlRewriter, When_UndeclaredEntityAppears_Then_DocumentIsRejected)
{
    auto rewriter = Create();
    const std::string input = "<prop xmlns=\"DAV:\">&unknown;</prop>";

    EXPECT_THROW((void)rewriter->Transform(Bytes(input), true), dav::XmlError);
}

TEST_F(Given_DavXmlRewriter, When_InputEndsBeforeClosingTag_Then_DocumentIsRejected)
{
    auto rewriter = Create();
    const std::string input = "<prop xmlns=\"DAV:\">";

    EXPECT_THROW((void)rewriter->Transform(Bytes(input), true), dav::XmlError);
}

TEST_F(Given_DavXmlRewriter, When_PeerHrefTargetsExternalServer_Then_ResponseIsRejected)
{
    auto rewriter = Create();
    const std::string input = "<response xmlns=\"DAV:\">"
                              "<href>http://other.example.com/docs/a</href></response>";

    EXPECT_THROW((void)rewriter->Transform(Bytes(input), true), dav::PathError);
}

TEST_F(Given_DavXmlRewriter, When_XmlNestingExceedsLimit_Then_DocumentIsRejected)
{
    auto rewriter = Create();
    std::string input;
    for (unsigned index = 0; index < 65; ++index)
    {
        input += "<prop>";
    }

    EXPECT_THROW((void)rewriter->Transform(Bytes(input), false), dav::XmlError);
}

} // namespace tailgate::tests
