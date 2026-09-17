#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/drive/FileSystemForLocal.h>
#include <tailgate/net/http/Client.h>
#include <tailgate/net/http/Message.h>

#include "fakes/base/FakeTimeProvider.h"
#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/drive/FakeTcpStack.h"

namespace tailgate::tests
{

class Given_DriveFileSystem : public testing::Test
{
protected:
    Given_DriveFileSystem()
    {
        fakes::InstallFakeNetworkBindings(m_injector);
        m_injector.InstallSingleton<fakes::FakeTcpStack, wgengine::netstack::Stack>();
        m_stack = m_injector.create<std::shared_ptr<fakes::FakeTcpStack>>();
        m_fileSystem = &m_injector.create<drive::FileSystemForLocal&>();
        m_config.Domain("example.ts.net");
        m_config.MagicDnsDomain("example.ts.net");
        m_config.SelfKey("nodekey:" + std::string(64, 'b'));
        m_config.SelfAddresses({"100.64.0.1"});
        m_config.Capabilities({"drive:access"});
        types::netmap::PeerConfig peer;
        peer.NodeId(42);
        peer.Key("nodekey:" + std::string(64, 'a'));
        peer.Name("laptop.example.ts.net");
        peer.Addresses({"100.64.0.2"});
        peer.PeerApi4Port(12345);
        peer.Online(true);
        peer.Capabilities({"tailscale.com/cap/drive-sharer"});
        m_config.Peers({peer});
        m_fileSystem->SetNetworkConfig(m_config);
        m_client->EofAfterShutdown = true;
        m_stack->Peer->CanRead = [this]
        {
            return m_stack->Peer->Output.find("\r\n\r\n") != std::string::npos;
        };
    }

    void Start(std::string request, std::string response = {})
    {
        m_client->Input = std::move(request);
        m_stack->Peer->Input = std::move(response);
        m_fileSystem->HandleConn(std::make_unique<fakes::FakeTcpStream>(m_client));
    }

    void RunReady()
    {
        constexpr unsigned MaximumReadySteps = 8192;
        for (unsigned step = 0; step < MaximumReadySteps; ++step)
        {
            if (!m_fileSystem->Poll())
            {
                return;
            }
        }
        ADD_FAILURE() << "File-system work did not reach a blocked or complete state";
    }

    net::http::Response Response()
    {
        auto parser = m_injector.create<net::http::MessageParserFactory&>().Create(
            {.Kind = net::http::MessageKind::Response});
        return parser->DecodeResponse(m_client->Output);
    }

    std::string UploadedBody()
    {
        auto parser = m_injector.create<net::http::MessageParserFactory&>().Create({});
        const auto& text = m_stack->Peer->Output;
        std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t*>(text.data()),
                                            text.size());
        std::array<std::uint8_t, 4096> buffer{};
        std::string body;
        while (!parser->Complete() && !bytes.empty())
        {
            const auto progress = parser->Put(bytes, buffer);
            if (progress.Consumed == 0)
            {
                break;
            }
            bytes = bytes.subspan(progress.Consumed);
            body.append(reinterpret_cast<const char*>(buffer.data()), progress.BodyBytes);
        }
        if (!parser->Complete())
        {
            throw net::http::MessageError(net::http::MessageErrorKind::Truncated);
        }
        return body;
    }

    bool SentFixedBody(std::size_t length) const
    {
        const auto end = m_stack->Peer->Output.find("\r\n\r\n");
        return end != std::string::npos && m_stack->Peer->Output.size() - end - 4 >= length;
    }

    di::Injector m_injector;
    std::shared_ptr<fakes::FakeTcpStack> m_stack;
    std::shared_ptr<fakes::FakeTcpStreamState> m_client =
        std::make_shared<fakes::FakeTcpStreamState>();
    types::netmap::NetworkConfig m_config;
    drive::FileSystemForLocal* m_fileSystem = nullptr;
};

TEST_F(Given_DriveFileSystem, When_GetIsProxied_Then_PeerApiTargetAndResponseBodyAreCorrect)
{
    Start("GET /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n",
          "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata");

    RunReady();
    const auto response = Response();

    EXPECT_TRUE(m_stack->Peer->Output.starts_with("GET /v0/drive/docs/a HTTP/1.1\r\n"));
    EXPECT_EQ(response.Status(), 200);
    EXPECT_EQ(response.Body(), "data");
    EXPECT_FALSE(m_client->Shutdown);
    EXPECT_FALSE(m_client->Aborted);
}

TEST_F(Given_DriveFileSystem, When_PostIsProxied_Then_BodyAndConditionalResponseArePreserved)
{
    m_stack->Peer->CanRead = [this]
    {
        return SentFixedBody(4);
    };
    Start("POST /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "If-Match: \"example-etag\"\r\nContent-Length: 4\r\n\r\ndata",
          "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 6\r\n\r\ndenied");

    RunReady();
    const auto response = Response();
    const auto uploaded = m_stack->Connected ? UploadedBody() : std::string{};

    EXPECT_TRUE(m_stack->Peer->Output.starts_with("POST /v0/drive/docs/a HTTP/1.1\r\n"));
    EXPECT_NE(m_stack->Peer->Output.find("If-Match: \"example-etag\"\r\n"), std::string::npos);
    EXPECT_EQ(uploaded, "data");
    EXPECT_EQ(response.Status(), 412);
    EXPECT_EQ(response.Body(), "denied");
    EXPECT_FALSE(m_client->Shutdown);
}

TEST_F(Given_DriveFileSystem, When_PostIsAcceptedByExporter_Then_ResponseIsReturned)
{
    Start("POST /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Content-Length: 0\r\n\r\n",
          "HTTP/1.1 200 OK\r\nETag: \"example-etag\"\r\nContent-Length: 4\r\n\r\ndata");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 200);
    EXPECT_EQ(response.Body(), "data");
    EXPECT_NE(m_client->Output.find("ETag: \"example-etag\"\r\n"), std::string::npos);
    EXPECT_FALSE(m_client->Shutdown);
}

TEST_F(Given_DriveFileSystem, When_LargePutMeetsShortWrites_Then_BodyStreamsWithoutTruncation)
{
    const std::string body(1024U * 1024U, 'x');
    m_stack->Peer->WriteLimit = 1024;
    m_stack->Peer->CanRead = [this, length = body.size()]
    {
        return SentFixedBody(length);
    };
    Start(std::format("PUT /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: "
                      "100.100.100.100:8080\r\nContent-Length: {}\r\n\r\n{}",
                      body.size(),
                      body),
          "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");

    RunReady();
    const auto uploaded = UploadedBody();
    const auto response = Response();

    EXPECT_EQ(uploaded, body);
    EXPECT_EQ(response.Status(), 201);
    EXPECT_FALSE(m_client->Aborted);
}

TEST_F(Given_DriveFileSystem, When_MkcolHasFixedLengthBody_Then_ExporterSeesOriginalFraming)
{
    m_stack->Peer->CanRead = [this]
    {
        return SentFixedBody(4);
    };
    Start("MKCOL /example.ts.net/laptop/docs/new HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Content-Length: 4\r\n\r\ndata",
          "HTTP/1.1 415 Unsupported Media Type\r\nContent-Length: 0\r\n\r\n");

    RunReady();
    const auto response = Response();
    const auto body = UploadedBody();

    EXPECT_NE(m_stack->Peer->Output.find("Content-Length: 4\r\n"), std::string::npos);
    EXPECT_EQ(m_stack->Peer->Output.find("Transfer-Encoding:"), std::string::npos);
    EXPECT_EQ(body, "data");
    EXPECT_EQ(response.Status(), 415);
    EXPECT_FALSE(m_client->Shutdown);
}

TEST_F(Given_DriveFileSystem, When_UploadIsChunked_Then_BodyAndTrailersRemainChunked)
{
    m_stack->Peer->CanRead = [this]
    {
        return m_stack->Peer->Output.ends_with("X-Example-Trailer: yes\r\n\r\n");
    };
    Start("PUT /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Transfer-Encoding: chunked\r\nTrailer: X-Example-Trailer\r\n\r\n"
          "4\r\ndata\r\n0\r\nX-Example-Trailer: yes\r\n\r\n",
          "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");

    RunReady();
    const auto response = Response();
    const auto body = UploadedBody();

    EXPECT_NE(m_stack->Peer->Output.find("Transfer-Encoding: chunked\r\n"), std::string::npos);
    EXPECT_EQ(m_stack->Peer->Output.find("Content-Length:"), std::string::npos);
    EXPECT_TRUE(m_stack->Peer->Output.ends_with("X-Example-Trailer: yes\r\n\r\n"));
    EXPECT_EQ(body, "data");
    EXPECT_EQ(response.Status(), 201);
}

TEST_F(Given_DriveFileSystem, When_PeerRejectsBeforeUpload_Then_ErrorIsDeliveredAndBodyStops)
{
    const std::string body(128U * 1024U, 'x');
    Start(
        std::format("PUT /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: "
                    "100.100.100.100:8080\r\nContent-Length: {}\r\nExpect: 100-continue\r\n\r\n{}",
                    body.size(),
                    body),
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\ndenied");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 403);
    EXPECT_EQ(response.Body(), "denied");
    EXPECT_LT(m_stack->Peer->Output.size(), body.size());
    EXPECT_FALSE(m_client->Aborted);
}

TEST_F(Given_DriveFileSystem, When_DownloadClientStopsReading_Then_PeerInputIsBounded)
{
    const std::string body(1024U * 1024U, 'x');
    m_client->WriteBlocked = true;
    Start("GET /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n",
          std::format("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.size(), body));

    RunReady();

    EXPECT_LT(m_stack->Peer->ReadOffset, 64U * 1024U);
    EXPECT_TRUE(m_client->Output.empty());
    EXPECT_FALSE(m_client->Aborted);
}

TEST_F(Given_DriveFileSystem, When_SharingGrantIsRevoked_Then_InFlightConnectionIsCancelled)
{
    Start("GET /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n");
    RunReady();
    ASSERT_TRUE(m_stack->Connected.has_value());
    m_config.Capabilities({});

    m_fileSystem->SetNetworkConfig(m_config);

    EXPECT_TRUE(m_client->Aborted);
    EXPECT_TRUE(m_stack->Peer->Aborted);
}

TEST_F(Given_DriveFileSystem, When_HostIsUntrusted_Then_NoPeerIsDialed)
{
    Start("GET /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: other.example.com\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 403);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_OriginIsCrossSite_Then_NoPeerIsDialed)
{
    Start("PUT /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\nOrigin: "
          "http://other.example.com\r\nContent-Length: 0\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 403);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_MoveIsProxied_Then_DestinationAndTaggedConditionsAreRewritten)
{
    Start(
        "MOVE /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\nDestination: "
        "http://100.100.100.100:8080/example.ts.net/laptop/docs/b\r\nIf: "
        "</example.ts.net/laptop/docs/a> (<opaquelocktoken:example>)\r\n\r\n",
        "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 201);
    EXPECT_NE(m_stack->Peer->Output.find("Destination: /docs/b\r\n"), std::string::npos);
    EXPECT_NE(m_stack->Peer->Output.find("If: </docs/a> (<opaquelocktoken:example>)\r\n"),
              std::string::npos);
}

TEST_F(Given_DriveFileSystem, When_PropfindResponseIsProxied_Then_HrefsAreRewrittenInStreamingXml)
{
    const std::string xml =
        "<multistatus xmlns=\"DAV:\"><response><href>/docs/a</href></response></multistatus>";
    Start("PROPFIND /example.ts.net/laptop/docs/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\nDepth: "
          "1\r\n\r\n",
          std::format("HTTP/1.1 207 Multi-Status\r\nContent-Type: "
                      "application/xml\r\nContent-Length: {}\r\n\r\n{}",
                      xml.size(),
                      xml));

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("<href>/example.ts.net/laptop/docs/a</href>"),
              std::string::npos);
}

TEST_F(Given_DriveFileSystem, When_ErrorXmlHasMixedCaseMediaType_Then_HrefsAndStatusArePreserved)
{
    const std::string xml = "<error xmlns=\"DAV:\"><response><href>/docs/a</href>"
                            "</response></error>";
    Start("PROPFIND /example.ts.net/laptop/docs/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Depth: 1\r\n\r\n",
          std::format("HTTP/1.1 403 Forbidden\r\nContent-Type: Application/XML; charset=utf-8\r\n"
                      "Content-Length: {}\r\n\r\n{}",
                      xml.size(),
                      xml));

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 403);
    EXPECT_NE(response.Body().find("<href>/example.ts.net/laptop/docs/a</href>"),
              std::string::npos);
}

TEST_F(Given_DriveFileSystem, When_ErrorMediaTypeOnlyStartsWithXml_Then_BodyIsNotParsedAsXml)
{
    Start("PROPFIND /example.ts.net/laptop/docs/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n",
          "HTTP/1.1 403 Forbidden\r\nContent-Type: application/xml-other\r\n"
          "Content-Length: 6\r\n\r\ndenied");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 403);
    EXPECT_EQ(response.Body(), "denied");
}

TEST_F(Given_DriveFileSystem, When_PutHasIfMatch_Then_ConditionAndExporterDenialArePreserved)
{
    Start("PUT /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "If-Match: \"example-version\"\r\nContent-Length: 4\r\n\r\ndata",
          "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 6\r\n\r\ndenied");

    RunReady();
    const auto response = Response();

    EXPECT_NE(m_stack->Peer->Output.find("If-Match: \"example-version\"\r\n"), std::string::npos);
    EXPECT_EQ(response.Status(), 412);
    EXPECT_EQ(response.Body(), "denied");
    EXPECT_FALSE(m_client->Aborted);
}

TEST_F(Given_DriveFileSystem, When_ExporterAcceptsConditionalPut_Then_SuccessIsPreserved)
{
    Start("PUT /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "If-Match: \"missing-version\"\r\nContent-Length: 0\r\n\r\n",
          "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_NE(m_stack->Peer->Output.find("If-Match: \"missing-version\"\r\n"), std::string::npos);
    EXPECT_EQ(response.Status(), 201);
    EXPECT_FALSE(m_client->Aborted);
}

TEST_F(Given_DriveFileSystem, When_PutHasIfNoneMatch_Then_CreateOnlyConditionIsPreserved)
{
    Start("PUT /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "If-None-Match: *\r\nContent-Length: 0\r\n\r\n",
          "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_NE(m_stack->Peer->Output.find("If-None-Match: *\r\n"), std::string::npos);
    EXPECT_EQ(response.Status(), 412);
    EXPECT_FALSE(m_client->Aborted);
}

TEST_F(Given_DriveFileSystem, When_PutHasDateCondition_Then_DateAndLockDenialArePreserved)
{
    Start("PUT /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "If-Unmodified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\nContent-Length: 0\r\n\r\n",
          "HTTP/1.1 423 Locked\r\nContent-Length: 6\r\n\r\nlocked");

    RunReady();
    const auto response = Response();

    EXPECT_NE(m_stack->Peer->Output.find("If-Unmodified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n"),
              std::string::npos);
    EXPECT_EQ(response.Status(), 423);
    EXPECT_EQ(response.Body(), "locked");
    EXPECT_FALSE(m_client->Aborted);
}

namespace
{

constexpr std::string_view Get =
    "GET /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n";
constexpr std::string_view Ok = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata";
constexpr std::string_view Options = "OPTIONS / HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n";

} // namespace

TEST_F(Given_DriveFileSystem, When_SequentialGetsComplete_Then_BothConnectionsAreReused)
{
    Start(std::string(Get), std::string(Ok));
    RunReady();
    ASSERT_EQ(Response().Body(), "data");
    ASSERT_EQ(m_stack->Connections, 1U);
    m_client->Output.clear();

    m_client->Input += Get;
    m_stack->Peer->Input += Ok;
    // A real peer produces its next response only after the next request was sent.
    const auto previousBytes = m_stack->Peer->Output.size();
    m_stack->Peer->CanRead = [this, previousBytes]
    {
        return m_stack->Peer->Output.size() > previousBytes;
    };
    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Body(), "data");
    EXPECT_EQ(m_stack->Connections, 1U);
    EXPECT_FALSE(m_client->Shutdown);
    EXPECT_FALSE(m_stack->Peer->Closed);
    EXPECT_FALSE(m_stack->Peer->Shutdown);
    EXPECT_FALSE(response.Headers().contains("connection"));
    EXPECT_EQ(m_stack->Peer->Output.find("Connection: close"), std::string::npos);
}

TEST_F(Given_DriveFileSystem, When_VirtualRequestsArePipelined_Then_ResponsesRemainOrdered)
{
    Start(std::string(Options) +
          "GET / HTTP/1.1\r\nHost: 100.100.100.100:8080\r\nConnection: close\r\n\r\n");

    RunReady();
    const auto first = m_client->Output.find("HTTP/1.1 200");
    const auto second = m_client->Output.find("HTTP/1.1 405");

    EXPECT_EQ(first, 0U);
    EXPECT_NE(second, std::string::npos);
    EXPECT_GT(second, first);
    EXPECT_TRUE(m_client->Shutdown);
    EXPECT_EQ(m_stack->Connections, 0U);
}

TEST_F(Given_DriveFileSystem, When_LocalClientExplicitlyCloses_Then_IdlePeerServesAnotherClient)
{
    Start("GET /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Connection: keep-alive, CLOSE\r\n\r\n",
          std::string(Ok));
    RunReady();
    ASSERT_TRUE(m_client->Shutdown);
    auto nextClient = std::make_shared<fakes::FakeTcpStreamState>();
    nextClient->Input = Get;
    const auto previousBytes = m_stack->Peer->Output.size();
    m_stack->Peer->Input += Ok;
    m_stack->Peer->CanRead = [this, previousBytes]
    {
        return m_stack->Peer->Output.size() > previousBytes;
    };

    m_fileSystem->HandleConn(std::make_unique<fakes::FakeTcpStream>(nextClient));
    RunReady();

    EXPECT_EQ(m_stack->Connections, 1U);
    EXPECT_NE(nextClient->Output.find("data"), std::string::npos);
    EXPECT_FALSE(nextClient->Shutdown);
}

TEST_F(Given_DriveFileSystem, When_ExporterCloses_Then_LocalSessionSurvivesWithFreshPeerConnection)
{
    Start(std::string(Get),
          "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 4\r\n\r\ndata");
    RunReady();
    ASSERT_TRUE(m_stack->Peer->Closed);
    m_client->Output.clear();
    m_stack->Peer = std::make_shared<fakes::FakeTcpStreamState>();
    m_stack->Peer->CanRead = [this]
    {
        return !m_stack->Peer->Output.empty();
    };

    m_client->Input += Get;
    m_stack->Peer->Input = Ok;
    RunReady();

    EXPECT_EQ(m_stack->Connections, 2U);
    EXPECT_EQ(Response().Body(), "data");
    EXPECT_FALSE(m_client->Shutdown);
}

TEST_F(Given_DriveFileSystem, When_ExporterClosesIdleConnection_Then_NextRequestUsesFreshConnection)
{
    Start(std::string(Get), std::string(Ok));
    RunReady();
    auto oldPeer = m_stack->Peer;
    oldPeer->Eof = true;
    oldPeer->CanRead = {};
    m_stack->Peer = std::make_shared<fakes::FakeTcpStreamState>();
    m_stack->Peer->CanRead = [this]
    {
        return !m_stack->Peer->Output.empty();
    };
    m_stack->Peer->Input = Ok;
    m_client->Output.clear();

    m_client->Input += Get;
    RunReady();

    EXPECT_EQ(m_stack->Connections, 2U);
    EXPECT_TRUE(oldPeer->Aborted);
    EXPECT_EQ(Response().Status(), 200);
}

TEST_F(Given_DriveFileSystem, When_IdlePeerGrantIsRevoked_Then_PoolAndPersistentCatalogAreUpdated)
{
    Start(std::string(Get), std::string(Ok));
    RunReady();
    m_client->Output.clear();
    m_config.Peers({});

    m_fileSystem->SetNetworkConfig(m_config);
    m_client->Input += Get;
    RunReady();

    EXPECT_TRUE(m_stack->Peer->Aborted);
    EXPECT_FALSE(m_client->Aborted);
    EXPECT_EQ(Response().Status(), 404);
    EXPECT_EQ(m_stack->Connections, 1U);
}

TEST_F(Given_DriveFileSystem, When_IdleDeadlinePasses_Then_LocalAndPooledConnectionsAreRetired)
{
    Start(std::string(Get), std::string(Ok));
    RunReady();
    const auto deadline = m_fileSystem->NextDeadline();
    ASSERT_TRUE(deadline.has_value());
    auto& time = dynamic_cast<fakes::FakeTimeProvider&>(m_injector.create<base::TimeProvider&>());

    time.Set(*deadline);
    RunReady();

    EXPECT_TRUE(m_client->Aborted);
    EXPECT_TRUE(m_stack->Peer->Closed);
    EXPECT_FALSE(m_fileSystem->NextDeadline().has_value());
}

TEST_F(Given_DriveFileSystem, When_ClientSendsEofBetweenRequests_Then_NoSpuriousErrorIsWritten)
{
    Start(std::string(Options));
    RunReady();
    const auto output = m_client->Output;

    m_client->Eof = true;
    RunReady();

    EXPECT_EQ(m_client->Output, output);
    EXPECT_TRUE(m_client->Closed);
    EXPECT_FALSE(m_client->Aborted);
}

TEST_F(Given_DriveFileSystem, When_Http10RequestsKeepAlive_Then_ProxyClosesClientConnection)
{
    Start("OPTIONS / HTTP/1.0\r\nHost: 100.100.100.100:8080\r\nConnection: keep-alive\r\n\r\n");

    RunReady();

    EXPECT_TRUE(m_client->Output.starts_with("HTTP/1.0 200"));
    EXPECT_TRUE(m_client->Shutdown);
    EXPECT_EQ(Response().Headers().at("connection"), "close");
}

TEST_F(Given_DriveFileSystem, When_LocalRejectionLeavesUnreadBody_Then_PipelineIsNotInterpreted)
{
    Start("PUT / HTTP/1.1\r\nHost: other.example.com\r\nContent-Length: 4\r\n\r\ndata" +
          std::string(Get));

    RunReady();

    EXPECT_EQ(Response().Status(), 403);
    EXPECT_TRUE(m_client->Shutdown);
    EXPECT_EQ(m_stack->Connections, 0U);
}

TEST_F(Given_DriveFileSystem, When_RejectedVirtualPutBodyIsConsumed_Then_NextRequestCanProceed)
{
    Start("PUT / HTTP/1.1\r\nHost: 100.100.100.100:8080\r\nContent-Length: 4\r\n\r\ndata" +
              std::string(Get),
          std::string(Ok));

    RunReady();
    const auto first = m_client->Output.find("HTTP/1.1 405");
    const auto second = m_client->Output.find("HTTP/1.1 200");

    EXPECT_EQ(first, 0U);
    EXPECT_NE(second, std::string::npos);
    EXPECT_GT(second, first);
    EXPECT_FALSE(m_client->Shutdown);
    EXPECT_EQ(m_stack->Connections, 1U);
}

TEST_F(Given_DriveFileSystem,
       When_RequestHeadersAreMalformed_Then_ErrorClosesWithoutAccessingMissingHead)
{
    Start("GET / HTTP/1.1\r\nMalformed header\r\n\r\n");

    RunReady();

    EXPECT_EQ(Response().Status(), 400);
    EXPECT_TRUE(m_client->Shutdown);
    EXPECT_EQ(m_stack->Connections, 0U);
}

TEST_F(Given_DriveFileSystem, When_CloseDelimitedResponseEnds_Then_OnlyLocalSessionPersists)
{
    Start(std::string(Get), "HTTP/1.1 200 OK\r\n\r\ndata");
    m_stack->Peer->Eof = true;

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Body(), "data");
    EXPECT_TRUE(m_stack->Peer->Closed);
    EXPECT_FALSE(m_client->Shutdown);
    EXPECT_EQ(response.Headers().at("transfer-encoding"), "chunked");
}

TEST_F(Given_DriveFileSystem, When_ResponseIsTruncated_Then_ConnectionCannotEnterPool)
{
    Start(std::string(Get), "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\ndata");
    m_stack->Peer->Eof = true;

    RunReady();

    EXPECT_TRUE(m_stack->Peer->Aborted);
    EXPECT_TRUE(m_client->Aborted);
    EXPECT_FALSE(m_fileSystem->NextDeadline().has_value());
}

TEST_F(Given_DriveFileSystem, When_ExtraResponseBytesArrive_Then_ConnectionCannotEnterPool)
{
    Start(std::string(Get), std::string(Ok) + std::string(Ok));

    RunReady();

    EXPECT_EQ(Response().Body(), "data");
    EXPECT_TRUE(m_stack->Peer->Closed);
    EXPECT_FALSE(m_client->Shutdown);
}

TEST_F(Given_DriveFileSystem, When_ConnectionFailsDuringPut_Then_MutationIsNotRetried)
{
    Start("PUT /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Content-Length: 4\r\n\r\ndata");
    m_stack->Peer->Aborted = true;

    RunReady();

    EXPECT_EQ(Response().Status(), 502);
    EXPECT_EQ(m_stack->Connections, 1U);
    EXPECT_TRUE(m_client->Shutdown);
}

TEST_F(Given_DriveFileSystem, When_ConcurrentPeerConnectionsBecomeIdle_Then_PerPeerPoolIsBounded)
{
    std::vector<std::shared_ptr<fakes::FakeTcpStreamState>> peers;
    constexpr unsigned ConcurrentRequests = 3;
    for (unsigned index = 0; index < ConcurrentRequests; ++index)
    {
        auto local = std::make_shared<fakes::FakeTcpStreamState>();
        local->Input = Get;
        m_stack->Peer = std::make_shared<fakes::FakeTcpStreamState>();
        peers.push_back(m_stack->Peer);
        m_fileSystem->HandleConn(std::make_unique<fakes::FakeTcpStream>(local));
        RunReady();
    }
    ASSERT_EQ(m_stack->Connections, ConcurrentRequests);

    for (const auto& peer : peers)
    {
        peer->Input = Ok;
    }
    RunReady();
    const auto closed = std::ranges::count_if(peers,
                                              [](const auto& peer)
                                              {
                                                  return peer->Closed;
                                              });

    EXPECT_EQ(closed, 1);
    EXPECT_FALSE(peers[0]->Aborted);
    EXPECT_FALSE(peers[1]->Aborted);
}

TEST_F(Given_DriveFileSystem, When_SessionChangesRemote_Then_PoolDoesNotReuseAnotherPeersStream)
{
    Start(std::string(Get), std::string(Ok));
    RunReady();
    auto originalPeer = m_stack->Peer;
    originalPeer->CanRead = {};
    auto remotes = m_config.Peers();
    auto second = remotes.front();
    second.NodeId(43);
    second.Key("nodekey:" + std::string(64, 'c'));
    second.Name("other.example.ts.net");
    second.Addresses({"100.64.0.3"});
    remotes.push_back(second);
    m_config.Peers(std::move(remotes));
    m_fileSystem->SetNetworkConfig(m_config);
    m_client->Output.clear();
    m_stack->Peer = std::make_shared<fakes::FakeTcpStreamState>();
    m_stack->Peer->CanRead = [this]
    {
        return !m_stack->Peer->Output.empty();
    };
    m_stack->Peer->Input = Ok;

    m_client->Input +=
        "GET /example.ts.net/other/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n";
    RunReady();

    EXPECT_EQ(m_stack->Connections, 2U);
    EXPECT_EQ(m_stack->Connected->Address, net::IpAddress::Parse("100.64.0.3"));
    EXPECT_EQ(Response().Body(), "data");
    EXPECT_FALSE(originalPeer->Closed);
    EXPECT_FALSE(originalPeer->Aborted);
}

TEST_F(Given_DriveFileSystem, When_PeerDialFails_Then_GatewayErrorIsReturnedWithoutRetry)
{
    Start(std::string(Get));
    m_stack->FailConnections = true;

    RunReady();

    EXPECT_EQ(Response().Status(), 502);
    EXPECT_EQ(m_stack->Connections, 1U);
    EXPECT_TRUE(m_client->Shutdown);
}

TEST_F(Given_DriveFileSystem, When_PeerSendsContinue_Then_ClientCanResumeTheUpload)
{
    Start("PUT /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Expect: 100-continue\r\nContent-Length: 4\r\n\r\n",
          "HTTP/1.1 100 Continue\r\n\r\n");
    RunReady();
    ASSERT_NE(m_client->Output.find("HTTP/1.1 100 Continue"), std::string::npos);
    m_stack->Peer->CanRead = [this]
    {
        return SentFixedBody(4);
    };

    m_client->Input += "data";
    m_stack->Peer->Input += "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
    RunReady();
    const auto response = Response();
    const auto uploaded = UploadedBody();

    EXPECT_EQ(response.Status(), 201);
    EXPECT_EQ(uploaded, "data");
}

TEST_F(Given_DriveFileSystem,
       When_UpstreamBodyIsTruncated_Then_ClientDoesNotReceiveSuccessTerminator)
{
    m_stack->Peer->Eof = true;
    Start("GET /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n",
          "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\ndata");

    RunReady();

    EXPECT_TRUE(m_client->Aborted);
    EXPECT_THROW((void)Response(), net::http::MessageError);
}

TEST_F(Given_DriveFileSystem, When_HeadHasRepresentationLength_Then_NoBodyIsReadOrWritten)
{
    Start("HEAD /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n",
          "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n");

    RunReady();
    auto parser = m_injector.create<net::http::MessageParserFactory&>().Create(
        {.Kind = net::http::MessageKind::Response, .SkipBody = true});
    const auto response = parser->DecodeResponse(m_client->Output);

    EXPECT_EQ(response.Status(), 200);
    EXPECT_EQ(response.Headers().at("content-length"), "1234");
    EXPECT_TRUE(response.Body().empty());
    EXPECT_FALSE(m_client->Aborted);
}

TEST_F(Given_DriveFileSystem, When_DownloadedFileIsXml_Then_ActualFileContentIsNeverRewritten)
{
    const std::string body = "<response xmlns=\"DAV:\"><href>/docs/a</href></response>";
    Start("GET /example.ts.net/laptop/docs/file.xml HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n",
          std::format("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nETag: \"example\"\r\n"
                      "Content-Length: {}\r\n\r\n{}",
                      body.size(),
                      body));

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Body(), body);
    EXPECT_EQ(response.Headers().at("etag"), "\"example\"");
}

TEST_F(Given_DriveFileSystem, When_LockIsRefreshed_Then_TokenIsPreservedAndLockrootIsRewritten)
{
    const std::string body = "<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>"
                             "<D:locktoken><D:href>opaquelocktoken:example</D:href></D:locktoken>"
                             "<D:lockroot><D:href>/docs/a</D:href></D:lockroot>"
                             "</D:activelock></D:lockdiscovery></D:prop>";
    Start("LOCK /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "If: (<opaquelocktoken:example>)\r\nTimeout: Second-60\r\n\r\n",
          std::format("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n"
                      "Lock-Token: <opaquelocktoken:example>\r\nContent-Length: {}\r\n\r\n{}",
                      body.size(),
                      body));

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Headers().at("lock-token"), "<opaquelocktoken:example>");
    EXPECT_NE(response.Body().find("<D:href>/example.ts.net/laptop/docs/a</D:href>"),
              std::string::npos);
    EXPECT_NE(m_stack->Peer->Output.find("If: (<opaquelocktoken:example>)"), std::string::npos);
}

TEST_F(Given_DriveFileSystem,
       When_ExporterLocksDecodedUnicodeFilename_Then_CompleteLockResponseReachesClient)
{
    const std::string body = "<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>"
                             "<D:locktoken><D:href>opaquelocktoken:example</D:href></D:locktoken>"
                             "<D:lockroot><D:href>/docs/雪 100% %2F.txt</D:href></D:lockroot>"
                             "</D:activelock></D:lockdiscovery></D:prop>";
    Start("LOCK /example.ts.net/laptop/docs/%E9%9B%AA%20100%25%20%252F.txt HTTP/1.1\r\n"
          "Host: 100.100.100.100:8080\r\nTimeout: Second-60\r\n\r\n",
          std::format("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n"
                      "Lock-Token: <opaquelocktoken:example>\r\nContent-Length: {}\r\n\r\n{}",
                      body.size(),
                      body));

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 200);
    EXPECT_EQ(response.Headers().at("lock-token"), "<opaquelocktoken:example>");
    EXPECT_NE(response.Body().find("<D:href>/example.ts.net/laptop/docs/"
                                   "%E9%9B%AA%20100%25%20%252F.txt</D:href>"),
              std::string::npos);
    EXPECT_FALSE(m_client->Aborted);
}

TEST_F(Given_DriveFileSystem, When_BackpressuredDownloadResumes_Then_AllFileBytesAreDelivered)
{
    const std::string body(1024U * 1024U, 'x');
    m_client->WriteBlocked = true;
    m_client->WriteLimit = 512;
    Start("GET /example.ts.net/laptop/docs/a HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n",
          std::format("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.size(), body));
    RunReady();
    ASSERT_LT(m_stack->Peer->ReadOffset, 64U * 1024U);

    m_client->WriteBlocked = false;
    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Body(), body);
    EXPECT_FALSE(m_client->Aborted);
    EXPECT_FALSE(m_client->Shutdown);
}

TEST_F(Given_DriveFileSystem, When_RootIsEnumerated_Then_OnlyTailnetDirectoryIsReturned)
{
    Start("PROPFIND / HTTP/1.1\r\nHost: 100.100.100.100:8080\r\nDepth: 1\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("<D:href>/example.ts.net/</D:href>"), std::string::npos);
    EXPECT_EQ(response.Body().find("<D:href>/example.ts.net/laptop/</D:href>"), std::string::npos);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_VirtualListingIsStreamed_Then_ChunkedResponseRemainsPersistent)
{
    Start("PROPFIND /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\nDepth: 1\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(m_client->Output.find("Transfer-Encoding: chunked\r\n"), std::string::npos);
    EXPECT_EQ(m_client->Output.find("Content-Length:"), std::string::npos);
    EXPECT_TRUE(m_client->Output.ends_with("0\r\n\r\n"));
    EXPECT_NE(response.Body().find("<D:href>/example.ts.net/laptop/</D:href>"), std::string::npos);
    EXPECT_TRUE(response.Body().ends_with("</D:multistatus>"));
    EXPECT_FALSE(m_client->Shutdown);
    EXPECT_FALSE(m_client->Aborted);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_Http10VirtualListingIsStreamed_Then_ResponseIsCloseDelimited)
{
    Start("PROPFIND /example.ts.net/ HTTP/1.0\r\nHost: 100.100.100.100:8080\r\nDepth: 1\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 207);
    EXPECT_TRUE(m_client->Output.starts_with("HTTP/1.0 207"));
    EXPECT_EQ(m_client->Output.find("Transfer-Encoding:"), std::string::npos);
    EXPECT_EQ(m_client->Output.find("Content-Length:"), std::string::npos);
    EXPECT_NE(m_client->Output.find("Connection: close\r\n"), std::string::npos);
    EXPECT_TRUE(response.Body().ends_with("</D:multistatus>"));
    EXPECT_TRUE(m_client->Shutdown);
    EXPECT_FALSE(m_client->Aborted);
}

TEST_F(Given_DriveFileSystem, When_VirtualListingUnblocks_Then_AllEntriesResumeWithShortWrites)
{
    m_client->WriteBlocked = true;
    m_client->WriteLimit = 7;
    Start("PROPFIND /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\nDepth: 1\r\n\r\n");
    RunReady();
    ASSERT_TRUE(m_client->Output.empty());
    ASSERT_FALSE(m_client->Aborted);

    const bool blockedProgress = m_fileSystem->Poll();
    m_client->WriteBlocked = false;
    RunReady();
    const auto response = Response();

    EXPECT_FALSE(blockedProgress);
    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("<D:href>/example.ts.net/</D:href>"), std::string::npos);
    EXPECT_NE(response.Body().find("<D:href>/example.ts.net/laptop/</D:href>"), std::string::npos);
    EXPECT_TRUE(response.Body().ends_with("</D:multistatus>"));
    EXPECT_FALSE(m_client->Shutdown);
    EXPECT_FALSE(m_client->Aborted);
}

TEST_F(Given_DriveFileSystem,
       When_OptionsFollowsStreamedListing_Then_FinalChunkPrecedesNextResponse)
{
    Start("PROPFIND /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\nDepth: 1\r\n\r\n"
          "OPTIONS / HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n");

    RunReady();
    const auto boundary = m_client->Output.find("0\r\n\r\nHTTP/1.1 200");
    const auto closing = m_client->Output.find("</D:multistatus>");

    EXPECT_TRUE(m_client->Output.starts_with("HTTP/1.1 207"));
    EXPECT_NE(boundary, std::string::npos);
    EXPECT_NE(closing, std::string::npos);
    EXPECT_LT(closing, boundary);
    EXPECT_FALSE(m_client->Shutdown);
    EXPECT_FALSE(m_client->Aborted);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem,
       When_VirtualListingExceedsQuota_Then_ConnectionAbortsWithoutFinalChunk)
{
    std::vector<types::netmap::PeerConfig> peers;
    for (unsigned index = 0; index < 512; ++index)
    {
        auto peer = m_config.Peers().front();
        peer.NodeId(index + 1);
        peer.Name(std::format("peer{}.example.ts.net", index));
        peer.Key(std::format("nodekey:{:064x}", index + 1));
        peer.Addresses({std::format("100.64.{}.{}", index / 254 + 1, index % 254 + 1)});
        peers.push_back(std::move(peer));
    }
    m_config.Peers(std::move(peers));
    m_fileSystem->SetNetworkConfig(m_config);
    std::string query = "<propfind xmlns=\"DAV:\"><prop>";
    for (unsigned index = 0; index < 7; ++index)
    {
        query += std::format("<{}{}/>", std::string(8190, 'p'), index);
    }
    query += "</prop></propfind>";
    Start(std::format("PROPFIND /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
                      "Depth: 1\r\nContent-Length: {}\r\n\r\n{}",
                      query.size(),
                      query));
    std::optional<net::http::MessageErrorKind> error;

    RunReady();
    try
    {
        (void)Response();
    }
    catch (const net::http::MessageError& exception)
    {
        error = exception.Kind();
    }

    EXPECT_TRUE(m_client->Output.starts_with("HTTP/1.1 207"));
    EXPECT_NE(m_client->Output.find("<D:response>"), std::string::npos);
    EXPECT_EQ(m_client->Output.find("</D:multistatus>"), std::string::npos);
    EXPECT_FALSE(m_client->Output.ends_with("0\r\n\r\n"));
    EXPECT_EQ(error, net::http::MessageErrorKind::Truncated);
    EXPECT_TRUE(m_client->Aborted);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem,
       When_SelectedVirtualPropertiesAreRequested_Then_MissingPropertiesGetSeparateStatus)
{
    const std::string body =
        "<propfind xmlns=\"DAV:\"><prop><resourcetype/>"
        "<missing xmlns=\"https://example.com/properties\"/></prop></propfind>";
    Start(std::format("PROPFIND /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
                      "Depth: 0\r\nContent-Length: {}\r\n\r\n{}",
                      body.size(),
                      body));

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("<D:collection/>"), std::string::npos);
    EXPECT_NE(response.Body().find("HTTP/1.1 404 Not Found"), std::string::npos);
    EXPECT_NE(response.Body().find("https://example.com/properties"), std::string::npos);
    EXPECT_EQ(response.Body().find("displayname"), std::string::npos);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_PropertyNamesAreRequested_Then_ValuesAreOmitted)
{
    const std::string body = "<propfind xmlns=\"DAV:\"><propname/></propfind>";
    Start(std::format("PROPFIND /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
                      "Depth: 0\r\nContent-Length: {}\r\n\r\n{}",
                      body.size(),
                      body));

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("resourcetype"), std::string::npos);
    EXPECT_EQ(response.Body().find("<D:collection/>"), std::string::npos);
}

TEST_F(Given_DriveFileSystem, When_VirtualCollectionDeleteIsRequested_Then_MethodIsNotAllowed)
{
    Start("DELETE /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 405);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_VirtualHeadIsRequested_Then_MethodIsNotAllowedWithoutBody)
{
    Start("HEAD /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 405);
    EXPECT_TRUE(response.Body().empty());
}

TEST_F(Given_DriveFileSystem, When_VirtualGetIsRequested_Then_MethodIsNotAllowed)
{
    Start("GET /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 405);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_VirtualPostIsRequested_Then_MethodIsNotAllowed)
{
    Start("POST /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Content-Length: 0\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 405);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_VirtualLockIsRequested_Then_MethodIsNotAllowed)
{
    Start("LOCK /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Content-Length: 0\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 405);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_VirtualPropfindDepthIsInvalid_Then_RequestIsBad)
{
    Start("PROPFIND /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Depth: 2\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 400);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_VirtualOptionsIsRequested_Then_OfficialMethodsAreAdvertised)
{
    Start("OPTIONS / HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 200);
    EXPECT_NE(m_client->Output.find("Allow: OPTIONS, LOCK, DELETE, PROPPATCH, COPY, MOVE, "
                                    "UNLOCK, PROPFIND\r\n"),
              std::string::npos);
    EXPECT_NE(m_client->Output.find("MS-Author-Via: DAV\r\n"), std::string::npos);
}

TEST_F(Given_DriveFileSystem, When_PeerDirectoryDepthIsZero_Then_NoPeerConnectionIsNeeded)
{
    Start("PROPFIND /example.ts.net/laptop/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Depth: 0\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("<D:href>/example.ts.net/laptop/</D:href>"), std::string::npos);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_PeerDirectoryDepthIsOmitted_Then_OnlyPeerDirectoryIsReturned)
{
    Start("PROPFIND /example.ts.net/laptop/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 207);
    EXPECT_NE(response.Body().find("<D:href>/example.ts.net/laptop/</D:href>"), std::string::npos);
    EXPECT_EQ(response.Body().find("<D:href>/example.ts.net/</D:href>"), std::string::npos);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_PeerDirectoryDepthIsOne_Then_PeerIsQueried)
{
    Start("PROPFIND /example.ts.net/laptop/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Depth: 1\r\n\r\n",
          "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 403);
    EXPECT_TRUE(m_stack->Connected.has_value());
    EXPECT_TRUE(m_stack->Peer->Output.starts_with("PROPFIND /v0/drive/ HTTP/1.1\r\n"));
}

TEST_F(Given_DriveFileSystem, When_UnknownPeerDirectoryDepthIsZero_Then_NotFoundIsReturned)
{
    Start("PROPFIND /example.ts.net/unknown/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Depth: 0\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 404);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_PeerDirectoryLockHasZeroDepth_Then_LockingIsRejectedLocally)
{
    Start("LOCK /example.ts.net/laptop/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Depth: 0\r\nContent-Length: 0\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 405);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_VirtualProppatchIsMalformed_Then_BadRequestIsReturned)
{
    Start("PROPPATCH /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Content-Length: 0\r\n\r\n");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 400);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_VirtualPutHasBody_Then_DirectoryIsNotWritten)
{
    Start("PUT /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
          "Content-Length: 4\r\n\r\ndata");

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 405);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem,
       When_VirtualNamespacesExceedResponseLimit_Then_PartialListingCannotDecodeSuccessfully)
{
    std::vector<types::netmap::PeerConfig> peers;
    for (unsigned index = 0; index < 512; ++index)
    {
        auto peer = m_config.Peers().front();
        peer.NodeId(index + 1);
        peer.Name(std::format("device{}.example.ts.net", index));
        peers.push_back(std::move(peer));
    }
    m_config.Peers(std::move(peers));
    m_fileSystem->SetNetworkConfig(m_config);
    std::string body = "<propfind xmlns=\"DAV:\"><prop>";
    for (unsigned index = 0; index < 40; ++index)
    {
        body += std::format("<property{} xmlns=\"https://example.com/{}/{}\"/>",
                            index,
                            index,
                            std::string(1000, 'a'));
    }
    body += "</prop></propfind>";
    Start(std::format("PROPFIND /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
                      "Depth: 1\r\nContent-Length: {}\r\n\r\n{}",
                      body.size(),
                      body));
    std::optional<net::http::MessageErrorKind> error;

    RunReady();
    try
    {
        (void)Response();
    }
    catch (const net::http::MessageError& exception)
    {
        error = exception.Kind();
    }

    EXPECT_TRUE(m_client->Output.starts_with("HTTP/1.1 207"));
    EXPECT_EQ(m_client->Output.find("</D:multistatus>"), std::string::npos);
    EXPECT_FALSE(m_client->Output.ends_with("0\r\n\r\n"));
    EXPECT_EQ(error, net::http::MessageErrorKind::Truncated);
    EXPECT_TRUE(m_client->Aborted);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

TEST_F(Given_DriveFileSystem, When_VirtualQueryContainsDoctype_Then_ItIsRejected)
{
    const std::string body = "<!DOCTYPE propfind SYSTEM \"https://example.com/invalid.dtd\">"
                             "<propfind xmlns=\"DAV:\"><allprop/></propfind>";
    Start(std::format("PROPFIND /example.ts.net/ HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n"
                      "Depth: 0\r\nContent-Length: {}\r\n\r\n{}",
                      body.size(),
                      body));

    RunReady();
    const auto response = Response();

    EXPECT_EQ(response.Status(), 400);
    EXPECT_FALSE(m_stack->Connected.has_value());
}

} // namespace tailgate::tests
