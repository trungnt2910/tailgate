#include <format>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/drive/driveimpl/compositedav/XmlRewriter.h>

#include "fakes/di/FakeNetworkBindings.h"

namespace tailgate::tests
{
namespace dav = drive::driveimpl::compositedav;

enum class QueryMethod
{
    Propfind,
    Proppatch,
};

class Given_XmlRewriterFactory : public testing::TestWithParam<QueryMethod>
{
protected:
    Given_XmlRewriterFactory()
    {
        fakes::InstallFakeNetworkBindings(m_injector);
        m_factory = &m_injector.create<dav::XmlRewriterFactory&>();
    }

    std::string Query() const
    {
        return GetParam() == QueryMethod::Propfind
                   ? "<propfind xmlns=\"DAV:\"><prop><displayname/></prop></propfind>"
                   : "<propertyupdate xmlns=\"DAV:\"><set><prop><displayname/>"
                     "</prop></set></propertyupdate>";
    }

    std::vector<dav::PropertyName> Parse(std::string_view input)
    {
        const auto bytes =
            std::span(reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
        return GetParam() == QueryMethod::Propfind ? m_factory->ParsePropfind(bytes).Properties
                                                   : m_factory->ParseProppatch(bytes);
    }

    std::string PropertyQuery(unsigned count, std::string_view nameSpace = "DAV:") const
    {
        std::string properties;
        for (unsigned index = 0; index < count; ++index)
        {
            properties += std::format("<P:p{}/>", index);
        }
        const auto group = std::format("<prop xmlns:P=\"{}\">{}</prop>", nameSpace, properties);
        return GetParam() == QueryMethod::Propfind
                   ? std::format("<propfind xmlns=\"DAV:\">{}</propfind>", group)
                   : std::format("<propertyupdate xmlns=\"DAV:\"><set>{}</set></propertyupdate>",
                                 group);
    }

    di::Injector m_injector;
    dav::XmlRewriterFactory* m_factory = nullptr;
};

TEST_P(Given_XmlRewriterFactory, When_QueryIsAtSizeLimit_Then_PropertiesAreParsed)
{
    auto input = Query();
    input.resize(64U * 1024U, ' ');

    const auto properties = Parse(input);

    EXPECT_EQ(properties,
              (std::vector<dav::PropertyName>{{.Namespace = "DAV:", .LocalName = "displayname"}}));
}

TEST_P(Given_XmlRewriterFactory, When_QueryExceedsSizeLimit_Then_LimitErrorIsReported)
{
    auto input = Query();
    input.resize(64U * 1024U + 1U, ' ');
    std::optional<dav::XmlErrorKind> error;

    try
    {
        (void)Parse(input);
    }
    catch (const dav::XmlError& exception)
    {
        error = exception.Kind();
    }

    EXPECT_EQ(error, dav::XmlErrorKind::Limit);
}

TEST_P(Given_XmlRewriterFactory, When_QueryHasDoctype_Then_ForbiddenMarkupIsReported)
{
    const auto input = "<!DOCTYPE propfind SYSTEM \"https://example.com/external.dtd\">" + Query();
    std::optional<dav::XmlErrorKind> error;

    try
    {
        (void)Parse(input);
    }
    catch (const dav::XmlError& exception)
    {
        error = exception.Kind();
    }

    EXPECT_EQ(error, dav::XmlErrorKind::ForbiddenMarkup);
}

TEST_P(Given_XmlRewriterFactory, When_PropertyCountIsAtLimit_Then_AllPropertiesAreParsed)
{
    const auto input = PropertyQuery(256);

    const auto properties = Parse(input);

    EXPECT_EQ(properties.size(), 256U);
}

TEST_P(Given_XmlRewriterFactory, When_PropertyCountExceedsLimit_Then_LimitErrorIsReported)
{
    const auto input = PropertyQuery(257);
    std::optional<dav::XmlErrorKind> error;

    try
    {
        (void)Parse(input);
    }
    catch (const dav::XmlError& exception)
    {
        error = exception.Kind();
    }

    EXPECT_EQ(error, dav::XmlErrorKind::Limit);
}

TEST_P(Given_XmlRewriterFactory, When_NamespaceExpansionExceedsLimit_Then_LimitErrorIsReported)
{
    const auto input = PropertyQuery(32, "https://example.com/" + std::string(4096, 'n'));
    ASSERT_LT(input.size(), 64U * 1024U);
    std::optional<dav::XmlErrorKind> error;

    try
    {
        (void)Parse(input);
    }
    catch (const dav::XmlError& exception)
    {
        error = exception.Kind();
    }

    EXPECT_EQ(error, dav::XmlErrorKind::Limit);
}

INSTANTIATE_TEST_SUITE_P(Methods,
                         Given_XmlRewriterFactory,
                         testing::Values(QueryMethod::Propfind, QueryMethod::Proppatch));

TEST_F(Given_XmlRewriterFactory, When_PropfindBodyIsEmpty_Then_AllPropertiesAreSelected)
{
    const std::span<const std::uint8_t> input;

    const auto query = m_factory->ParsePropfind(input);

    EXPECT_EQ(query.Selection, dav::PropertySelection::All);
    EXPECT_TRUE(query.Properties.empty());
}

TEST_F(Given_XmlRewriterFactory, When_ProppatchBodyIsEmpty_Then_MalformedErrorIsReported)
{
    const std::span<const std::uint8_t> input;
    std::optional<dav::XmlErrorKind> error;

    try
    {
        (void)m_factory->ParseProppatch(input);
    }
    catch (const dav::XmlError& exception)
    {
        error = exception.Kind();
    }

    EXPECT_EQ(error, dav::XmlErrorKind::Malformed);
}

} // namespace tailgate::tests
