#include <chrono>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/base/WallClock.h>
#include <tailgate/drive/driveimpl/compositedav/IfHeader.h>

#include "drive/driveimpl/Catalog.h"
#include "drive/driveimpl/dirfs/FileSystem.h"

#include "fakes/di/FakeNetworkBindings.h"

namespace tailgate::tests
{
namespace dav = drive::driveimpl::compositedav;

class DirectoryClock final : public base::WallClock
{
public:
    TimePoint Now() const noexcept override
    {
        return std::chrono::sys_days(std::chrono::year(2020) / 1 / 2);
    }
};

struct DirectoryRequest
{
    std::string Method;
    std::string Body{};
    std::vector<net::http::HeaderField> Fields{};
    unsigned Status = 0;
};

class Given_DirectoryFileSystem : public testing::TestWithParam<DirectoryRequest>
{
protected:
    Given_DirectoryFileSystem()
    {
        fakes::InstallFakeNetworkBindings(m_injector);
        m_injector.InstallSingleton<DirectoryClock, base::WallClock>();
        m_files = &m_injector.create<drive::driveimpl::dirfs::FileSystem&>();
        drive::Remote remote;
        remote.Name = "laptop";
        m_catalog->Domain = "example.ts.net";
        m_catalog->Remotes.push_back(remote);
        m_request.Target("/example.ts.net/");
        m_request.AddField({"Host", "example.com"});
    }

    net::http::Response Serve(std::string_view body = {})
    {
        auto response = m_files->Serve(m_request, body, m_catalog);
        if (!response.Collections)
        {
            return std::move(response.Metadata);
        }
        std::string xml;
        while (!response.Collections->Finished())
        {
            xml += response.Collections->Read(16U * 1024U);
        }
        return net::http::Response(
            response.Metadata.Status(), response.Metadata.Headers(), std::move(xml));
    }

    di::Injector m_injector;
    drive::driveimpl::dirfs::FileSystem* m_files = nullptr;
    net::http::MessageHead m_request;
    std::shared_ptr<drive::driveimpl::Catalog> m_catalog =
        std::make_shared<drive::driveimpl::Catalog>();
};

TEST_P(Given_DirectoryFileSystem, When_VirtualMethodIsRequested_Then_StatusMatchesReference)
{
    const auto& query = GetParam();
    m_request.Method(query.Method);
    m_request.AddField({"Content-Length", std::to_string(query.Body.size())});
    for (const auto& field : query.Fields)
    {
        m_request.AddField(field);
    }

    const auto response = Serve(query.Body);

    EXPECT_EQ(response.Status(), query.Status);
}

INSTANTIATE_TEST_SUITE_P(
    Methods,
    Given_DirectoryFileSystem,
    testing::Values(
        DirectoryRequest{.Method = "OPTIONS", .Status = 200},
        DirectoryRequest{.Method = "GET", .Status = 405},
        DirectoryRequest{.Method = "HEAD", .Status = 405},
        DirectoryRequest{.Method = "POST", .Status = 405},
        DirectoryRequest{.Method = "PUT", .Status = 201},
        DirectoryRequest{.Method = "PUT", .Body = "data", .Status = 405},
        DirectoryRequest{.Method = "MKCOL", .Status = 201},
        DirectoryRequest{.Method = "MKCOL", .Body = "data", .Status = 415},
        DirectoryRequest{.Method = "DELETE", .Status = 405},
        DirectoryRequest{.Method = "LOCK", .Status = 405},
        DirectoryRequest{.Method = "UNLOCK", .Status = 400},
        DirectoryRequest{
            .Method = "UNLOCK", .Fields = {{"Lock-Token", "<example>"}}, .Status = 409},
        DirectoryRequest{.Method = "COPY", .Status = 400},
        DirectoryRequest{.Method = "MOVE", .Status = 400},
        DirectoryRequest{.Method = "COPY", .Fields = {{"Destination", "/"}}, .Status = 403},
        DirectoryRequest{.Method = "MOVE", .Fields = {{"Destination", "/"}}, .Status = 412},
        DirectoryRequest{
            .Method = "MOVE", .Fields = {{"Destination", "/"}, {"Overwrite", "T"}}, .Status = 403},
        DirectoryRequest{
            .Method = "COPY", .Fields = {{"Destination", "/"}, {"Overwrite", "F"}}, .Status = 412},
        DirectoryRequest{
            .Method = "COPY", .Fields = {{"Destination", "/example.ts.net/"}}, .Status = 403},
        DirectoryRequest{
            .Method = "COPY", .Fields = {{"Destination", "/"}, {"Depth", "1"}}, .Status = 400},
        DirectoryRequest{
            .Method = "MOVE", .Fields = {{"Destination", "/"}, {"Depth", "0"}}, .Status = 400},
        DirectoryRequest{.Method = "COPY",
                         .Fields = {{"Destination", "http://other.example.com/"}},
                         .Status = 502},
        DirectoryRequest{
            .Method = "MKCOL", .Fields = {{"If", "(<opaquelocktoken:example>)"}}, .Status = 201},
        DirectoryRequest{.Method = "DELETE",
                         .Fields = {{"If", "<http://other.example.com/> (<example>)"}},
                         .Status = 412},
        DirectoryRequest{.Method = "DELETE",
                         .Fields = {{"If", "<http://example.com/> (<example>)"}},
                         .Status = 405},
        DirectoryRequest{.Method = "UNKNOWN", .Status = 400}));

TEST_F(Given_DirectoryFileSystem, When_OptionsIsRequested_Then_OfficialCapabilitiesAreAdvertised)
{
    m_request.Method("OPTIONS");

    const auto response = Serve();

    EXPECT_EQ(response.Headers().at("Allow"),
              "OPTIONS, LOCK, DELETE, PROPPATCH, COPY, MOVE, UNLOCK, PROPFIND");
    EXPECT_EQ(response.Headers().at("DAV"), "1, 2");
    EXPECT_EQ(response.Headers().at("MS-Author-Via"), "DAV");
}

TEST_F(Given_DirectoryFileSystem, When_AllPropertiesAreRequested_Then_DatesUseInjectedWallClock)
{
    m_request.Method("PROPFIND");
    m_request.AddField({"Depth", "0"});

    const auto response = Serve();

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("Thu, 02 Jan 2020 00:00:00 GMT"), std::string::npos);
    EXPECT_NE(response.Body().find("getlastmodified"), std::string::npos);
    EXPECT_NE(response.Body().find("creationdate"), std::string::npos);
    EXPECT_NE(response.Body().find("<D:exclusive/>"), std::string::npos);
    EXPECT_EQ(response.Body().find("getetag"), std::string::npos);
    EXPECT_EQ(response.Body().find("getcontentlength"), std::string::npos);
    EXPECT_EQ(response.Body().find("getcontenttype"), std::string::npos);
    EXPECT_EQ(response.Body().find("lockdiscovery"), std::string::npos);
}

TEST_F(Given_DirectoryFileSystem, When_FileOnlyPropertiesAreRequested_Then_TheyAreNotFound)
{
    m_request.Method("PROPFIND");
    m_request.AddField({"Depth", "0"});
    const std::string body = "<propfind xmlns=\"DAV:\"><prop><getcontentlength/>"
                             "<getcontenttype/><getetag/><lockdiscovery/></prop></propfind>";

    const auto response = Serve(body);

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("404 Not Found"), std::string::npos);
    EXPECT_EQ(response.Body().find("200 OK"), std::string::npos);
}

TEST_F(Given_DirectoryFileSystem, When_RootDepthIsOmitted_Then_WholeVirtualTreeIsListed)
{
    m_request.Method("PROPFIND");
    m_request.Target("/");

    const auto response = Serve();

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("<D:href>/</D:href>"), std::string::npos);
    EXPECT_NE(response.Body().find("<D:href>/example.ts.net/</D:href>"), std::string::npos);
    EXPECT_NE(response.Body().find("<D:href>/example.ts.net/laptop/</D:href>"), std::string::npos);
    EXPECT_NE(response.Body().find("<P:displayname xmlns:P=\"DAV:\"></P:displayname>"),
              std::string::npos);
}

TEST_F(Given_DirectoryFileSystem, When_RootDepthIsInfinite_Then_WholeVirtualTreeIsListed)
{
    m_request.Method("PROPFIND");
    m_request.Target("/");
    m_request.AddField({"Depth", "infinity"});

    const auto response = Serve();

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("<D:href>/example.ts.net/laptop/</D:href>"), std::string::npos);
}

TEST_F(Given_DirectoryFileSystem, When_TailnetDepthIsInfinite_Then_VirtualTreeIsSafelyListed)
{
    m_request.Method("PROPFIND");
    m_request.AddField({"Depth", "infinity"});

    const auto response = Serve();

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("<D:href>/example.ts.net/laptop/</D:href>"), std::string::npos);
}

TEST_F(Given_DirectoryFileSystem, When_DeadPropertyIsPatched_Then_PerPropertyDenialIsReturned)
{
    m_request.Method("PROPPATCH");
    const std::string body = "<propertyupdate xmlns=\"DAV:\"><set><prop>"
                             "<example xmlns=\"https://example.com/\"><value>data</value></example>"
                             "</prop></set></propertyupdate>";

    const auto response = Serve(body);

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("403 Forbidden"), std::string::npos);
    EXPECT_EQ(response.Body().find("200 OK"), std::string::npos);
    EXPECT_EQ(response.Body().find("424 Failed Dependency"), std::string::npos);
    EXPECT_NE(response.Body().find("https://example.com/"), std::string::npos);
    EXPECT_EQ(response.Body().find("<value>"), std::string::npos);
}

TEST_F(Given_DirectoryFileSystem, When_ProtectedAndDeadPropertiesArePatched_Then_PatchIsAtomic)
{
    m_request.Method("PROPPATCH");
    const std::string body =
        "<propertyupdate xmlns=\"DAV:\"><set><prop><displayname>data</displayname>"
        "<example xmlns=\"https://example.com/\">data</example></prop></set></propertyupdate>";

    const auto response = Serve(body);

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("403 Forbidden"), std::string::npos);
    EXPECT_NE(response.Body().find("424 Failed Dependency"), std::string::npos);
    EXPECT_NE(response.Body().find("cannot-modify-protected-property"), std::string::npos);
    EXPECT_EQ(response.Body().find("200 OK"), std::string::npos);
}

TEST_F(Given_DirectoryFileSystem, When_PropertyRemovalContainsValue_Then_ItIsRejected)
{
    m_request.Method("PROPPATCH");
    const std::string body = "<propertyupdate xmlns=\"DAV:\"><remove><prop><displayname>data"
                             "</displayname></prop></remove></propertyupdate>";

    const auto act = [&]
    {
        return Serve(body);
    };

    EXPECT_THROW((void)act(), dav::XmlError);
}

TEST_F(Given_DirectoryFileSystem, When_PropertyRemovalContainsComment_Then_ItIsRejected)
{
    m_request.Method("PROPPATCH");
    const std::string body = "<propertyupdate xmlns=\"DAV:\"><remove><prop><displayname><!--data-->"
                             "</displayname></prop></remove></propertyupdate>";

    const auto act = [&]
    {
        return Serve(body);
    };

    EXPECT_THROW((void)act(), dav::XmlError);
}

TEST_F(Given_DirectoryFileSystem, When_PropertyRemovalIsEmpty_Then_ProtectedDenialIsReturned)
{
    m_request.Method("PROPPATCH");
    const std::string body = "<propertyupdate xmlns=\"DAV:\"><remove><prop><displayname/>"
                             "</prop></remove></propertyupdate>";

    const auto response = Serve(body);

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("cannot-modify-protected-property"), std::string::npos);
}

TEST_F(Given_DirectoryFileSystem, When_PropertyUpdateIsEmptyXml_Then_ItIsRejected)
{
    m_request.Method("PROPPATCH");

    const auto act = [&]
    {
        return Serve();
    };

    EXPECT_THROW((void)act(), dav::XmlError);
}

TEST_F(Given_DirectoryFileSystem, When_IfConditionIsMalformed_Then_ItIsRejected)
{
    m_request.Method("DELETE");
    m_request.AddField({"If", "()"});

    const auto act = [&]
    {
        return Serve();
    };

    EXPECT_THROW((void)act(), dav::PathError);
}

TEST_F(Given_DirectoryFileSystem, When_PropfindIncludesBeforeAllprop_Then_SelectionIsAccepted)
{
    m_request.Method("PROPFIND");
    m_request.AddField({"Depth", "0"});
    const std::string body = "<propfind xmlns=\"DAV:\" xml:lang=\"en\"><include><getetag/>"
                             "</include><allprop/></propfind>";

    const auto response = Serve(body);

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("404 Not Found"), std::string::npos);
    EXPECT_NE(response.Body().find("getlastmodified"), std::string::npos);
}

TEST_F(Given_DirectoryFileSystem, When_PropfindPropertyContainsValue_Then_ItIsRejected)
{
    m_request.Method("PROPFIND");
    const std::string body = "<propfind xmlns=\"DAV:\"><prop><displayname>data</displayname>"
                             "</prop></propfind>";

    const auto act = [&]
    {
        return Serve(body);
    };

    EXPECT_THROW((void)act(), dav::XmlError);
}

TEST_F(Given_DirectoryFileSystem, When_PropfindPropertySelectionIsEmpty_Then_ItIsRejected)
{
    m_request.Method("PROPFIND");
    const std::string body = "<propfind xmlns=\"DAV:\"><prop/></propfind>";

    const auto act = [&]
    {
        return Serve(body);
    };

    EXPECT_THROW((void)act(), dav::XmlError);
}

} // namespace tailgate::tests
