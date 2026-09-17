#include <algorithm>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <gtest/gtest.h>

#include "drive/driveimpl/Catalog.h"
#include "drive/driveimpl/dirfs/FileSystem.h"

#include "fakes/di/FakeNetworkBindings.h"

namespace tailgate::tests
{
namespace dirfs = drive::driveimpl::dirfs;
namespace dav = drive::driveimpl::compositedav;

class Given_CollectionReader : public testing::Test
{
protected:
    Given_CollectionReader()
    {
        fakes::InstallFakeNetworkBindings(m_injector);
        m_catalog->Domain = "example.ts.net";
        drive::Remote remote;
        remote.Name = "laptop";
        m_catalog->Remotes.push_back(std::move(remote));
    }

    std::unique_ptr<dirfs::CollectionReader> Open(std::string_view body = {})
    {
        net::http::MessageHead request;
        request.Method("PROPFIND");
        request.Target("/example.ts.net/");
        request.AddField({"Depth", "1"});
        return m_injector.create<dirfs::FileSystem&>().Serve(request, body, m_catalog).Collections;
    }

    di::Injector m_injector;
    std::shared_ptr<drive::driveimpl::Catalog> m_catalog =
        std::make_shared<drive::driveimpl::Catalog>();
};

TEST_F(Given_CollectionReader, When_ReadingBegins_Then_OnlyXmlEnvelopeIsProduced)
{
    auto reader = Open();
    ASSERT_NE(reader, nullptr);

    const auto first = reader->Read(16U * 1024U);

    EXPECT_NE(first.find("<D:multistatus"), std::string::npos);
    EXPECT_EQ(first.find("<D:response>"), std::string::npos);
    EXPECT_FALSE(reader->Finished());
}

TEST_F(Given_CollectionReader, When_LaterPeerNameIsInvalid_Then_ItIsNotVisitedUntilItsTurn)
{
    m_catalog->Remotes.front().Name = "..";
    auto reader = Open();
    ASSERT_NE(reader, nullptr);
    std::optional<dav::PathErrorKind> error;

    const auto opening = reader->Read(16U * 1024U);
    const auto root = reader->Read(16U * 1024U);
    try
    {
        (void)reader->Read(16U * 1024U);
    }
    catch (const dav::PathError& exception)
    {
        error = exception.Kind();
    }

    EXPECT_NE(opening.find("<D:multistatus"), std::string::npos);
    EXPECT_NE(root.find("<D:href>/example.ts.net/</D:href>"), std::string::npos);
    EXPECT_EQ(error, dav::PathErrorKind::InvalidPath);
    EXPECT_FALSE(reader->Finished());
}

TEST_F(Given_CollectionReader, When_CallerReleasesCatalog_Then_ReaderKeepsItsSnapshotAlive)
{
    auto reader = Open();
    ASSERT_NE(reader, nullptr);
    std::weak_ptr<const drive::driveimpl::Catalog> snapshot = m_catalog;
    std::string xml;

    m_catalog.reset();
    while (!reader->Finished())
    {
        xml += reader->Read(16U * 1024U);
    }
    const bool retained = !snapshot.expired();
    reader.reset();

    EXPECT_TRUE(retained);
    EXPECT_NE(xml.find("<D:href>/example.ts.net/laptop/</D:href>"), std::string::npos);
    EXPECT_TRUE(xml.ends_with("</D:multistatus>"));
    EXPECT_TRUE(snapshot.expired());
}

TEST_F(Given_CollectionReader, When_ReadBudgetIsOneByte_Then_XmlIsDeliveredWithoutOversizedChunks)
{
    auto reader = Open();
    ASSERT_NE(reader, nullptr);
    std::string xml;
    std::size_t maximumChunk = 0;

    while (!reader->Finished())
    {
        const auto chunk = reader->Read(1);
        maximumChunk = std::max(maximumChunk, chunk.size());
        xml += chunk;
    }
    const auto eof = reader->Read(1);

    EXPECT_EQ(maximumChunk, 1U);
    EXPECT_TRUE(xml.starts_with("<?xml"));
    EXPECT_NE(xml.find("<D:href>/example.ts.net/laptop/</D:href>"), std::string::npos);
    EXPECT_TRUE(xml.ends_with("</D:multistatus>"));
    EXPECT_TRUE(eof.empty());
}

TEST_F(Given_CollectionReader, When_ReadBudgetIsZero_Then_InvalidStateIsReportedWithoutConsumingXml)
{
    auto reader = Open();
    ASSERT_NE(reader, nullptr);
    std::optional<dav::XmlErrorKind> error;

    try
    {
        (void)reader->Read(0);
    }
    catch (const dav::XmlError& exception)
    {
        error = exception.Kind();
    }
    const auto first = reader->Read(16U * 1024U);

    EXPECT_EQ(error, dav::XmlErrorKind::InvalidState);
    EXPECT_TRUE(first.starts_with("<?xml"));
}

TEST_F(Given_CollectionReader, When_ResponseExceedsLimit_Then_ErrorCannotBecomeSuccessfulEof)
{
    m_catalog->Remotes.clear();
    for (unsigned index = 0; index < 512; ++index)
    {
        drive::Remote remote;
        remote.Name = std::format("peer{}", index);
        m_catalog->Remotes.push_back(std::move(remote));
    }
    std::string query = "<propfind xmlns=\"DAV:\"><prop>";
    for (unsigned index = 0; index < 7; ++index)
    {
        query += std::format("<{}{}/>", std::string(8190, 'p'), index);
    }
    query += "</prop></propfind>";
    auto reader = Open(query);
    ASSERT_NE(reader, nullptr);
    std::optional<dav::XmlErrorKind> error;
    std::optional<dav::XmlErrorKind> retryError;
    std::size_t bytes = 0;
    bool closed = false;

    try
    {
        while (!reader->Finished())
        {
            const auto chunk = reader->Read(16U * 1024U);
            bytes += chunk.size();
            closed |= chunk.find("</D:multistatus>") != std::string::npos;
        }
    }
    catch (const dav::XmlError& exception)
    {
        error = exception.Kind();
    }
    try
    {
        (void)reader->Read(1);
    }
    catch (const dav::XmlError& exception)
    {
        retryError = exception.Kind();
    }

    EXPECT_EQ(error, dav::XmlErrorKind::Limit);
    EXPECT_EQ(retryError, dav::XmlErrorKind::InvalidState);
    EXPECT_GT(bytes, 0U);
    EXPECT_LE(bytes, 16U * 1024U * 1024U);
    EXPECT_FALSE(closed);
    EXPECT_FALSE(reader->Finished());
}

} // namespace tailgate::tests
