#include <array>
#include <span>
#include <string>
#include <string_view>

#include <gtest/gtest.h>

#include <tailgate/di/Bindings.h>
#include <tailgate/net/http/Client.h>
#include <tailgate/net/http/Message.h>

#include "fakes/di/FakeNetworkBindings.h"

namespace tailgate::tests
{
namespace http = net::http;

class Given_MessageParser : public testing::TestWithParam<const char*>
{
protected:
    Given_MessageParser()
    {
        fakes::InstallFakeNetworkBindings(m_injector);
    }

    std::unique_ptr<http::MessageParser> Create(http::ParserOptions options = {})
    {
        return m_injector.create<http::MessageParserFactory&>().Create(options);
    }

    static std::span<const std::uint8_t> Bytes(std::string_view text)
    {
        return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
    }

    di::Injector m_injector;
};

TEST_F(Given_MessageParser, When_BodyArrivesWithHeaders_Then_ParsingPausesBeforeBody)
{
    const std::string header =
        "PUT /docs/a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n";
    const auto input = header + "data";
    auto parser = Create();
    std::array<std::uint8_t, 16> body{};

    const auto progress = parser->Put(Bytes(input), body);

    EXPECT_EQ(progress.Consumed, header.size());
    EXPECT_EQ(progress.BodyBytes, 0U);
    EXPECT_TRUE(parser->HeaderComplete());
    EXPECT_FALSE(parser->Complete());
    EXPECT_EQ(parser->Head().Method(), "PUT");
    EXPECT_EQ(parser->Head().Target(), "/docs/a");
    EXPECT_TRUE(parser->KeepAlive());
}

TEST_F(Given_MessageParser, When_BodyBufferIsSmall_Then_UnconsumedInputProvidesBackpressure)
{
    auto parser = Create();
    (void)parser->Put(Bytes("PUT / HTTP/1.1\r\nContent-Length: 4\r\n\r\n"), {});
    ASSERT_TRUE(parser->HeaderComplete());
    std::array<std::uint8_t, 2> body{};

    const auto progress = parser->Put(Bytes("data"), body);

    EXPECT_EQ(progress.Consumed, 2U);
    EXPECT_EQ(progress.BodyBytes, 2U);
    EXPECT_EQ(std::string(body.begin(), body.end()), "da");
    EXPECT_FALSE(parser->Complete());
}

TEST_F(Given_MessageParser, When_ChunkedBodyCompletes_Then_NextMessageRemainsUnconsumed)
{
    auto parser = Create();
    (void)parser->Put(Bytes("PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), {});
    ASSERT_TRUE(parser->HeaderComplete());
    const std::string chunks = "4\r\ndata\r\n0\r\nX-Check: present\r\n\r\n";
    const auto input = chunks + "GET /next HTTP/1.1\r\n\r\n";
    std::array<std::uint8_t, 16> body{};

    const auto progress = parser->Put(Bytes(input), body);

    EXPECT_EQ(progress.Consumed, chunks.size());
    EXPECT_EQ(progress.BodyBytes, 4U);
    EXPECT_EQ(std::string(body.begin(), body.begin() + 4), "data");
    EXPECT_TRUE(parser->Complete());
}

TEST_F(Given_MessageParser, When_MessageHasTrailers_Then_TheyAreKeptSeparateFromInitialHeaders)
{
    auto parser = Create();
    (void)parser->Put(
        Bytes("PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nX-Check: first\r\n\r\n"), {});
    ASSERT_TRUE(parser->HeaderComplete());
    (void)parser->Put(Bytes("0\r\nX-Check: second\r\n\r\n"), {});
    ASSERT_TRUE(parser->Complete());

    const auto trailers = parser->Trailers();
    ASSERT_FALSE(trailers.empty());

    EXPECT_EQ(trailers.size(), 1U);
    EXPECT_EQ(trailers.front().Name(), "X-Check");
    EXPECT_EQ(trailers.front().Value(), "second");
}

TEST_F(Given_MessageParser, When_HeadersArriveInFragments_Then_CallerRetainsPartialFields)
{
    auto parser = Create();
    const std::string first = "PUT / HTTP/1.1\r\nContent-Len";
    const auto initial = parser->Put(Bytes(first), {});
    ASSERT_LE(initial.Consumed, first.size());
    const auto remainder = first.substr(initial.Consumed) + "gth: 0\r\n\r\n";

    const auto progress = parser->Put(Bytes(remainder), {});

    EXPECT_EQ(progress.Consumed, remainder.size());
    EXPECT_TRUE(parser->HeaderComplete());
    EXPECT_TRUE(parser->Complete());
}

TEST_F(Given_MessageParser, When_HeadResponseHasContentLength_Then_NoBodyIsExpected)
{
    auto parser =
        Create(http::ParserOptions{.Kind = http::MessageKind::Response, .SkipBody = true});
    const std::string input = "HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\n";

    (void)parser->Put(Bytes(input), {});

    EXPECT_TRUE(parser->Complete());
    EXPECT_EQ(parser->Head().Status(), 200U);
    EXPECT_TRUE(parser->KeepAlive());
}

TEST_F(Given_MessageParser, When_EofInterruptsFixedBody_Then_TruncationFailsTheExchange)
{
    auto parser = Create(http::ParserOptions{.Kind = http::MessageKind::Response});
    (void)parser->Put(Bytes("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n"), {});
    ASSERT_TRUE(parser->HeaderComplete());

    EXPECT_THROW(parser->Finish(), http::MessageError);

    EXPECT_FALSE(parser->Complete());
}

TEST_F(Given_MessageParser, When_ResponseIsDelimitedByEof_Then_FinishCompletesIt)
{
    auto parser = Create(http::ParserOptions{.Kind = http::MessageKind::Response});
    (void)parser->Put(Bytes("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"), {});
    std::array<std::uint8_t, 4> body{};

    const auto progress = parser->Put(Bytes("data"), body);
    parser->Finish();

    EXPECT_EQ(progress.BodyBytes, 4U);
    EXPECT_TRUE(parser->Complete());
    EXPECT_FALSE(parser->KeepAlive());
}

TEST_F(Given_MessageParser, When_ConnectionTokensIncludeClose_Then_PersistenceIsDisabled)
{
    auto parser = Create();

    (void)parser->Put(Bytes("GET / HTTP/1.1\r\nConnection: keep-alive, CLOSE\r\n\r\n"), {});

    EXPECT_TRUE(parser->Complete());
    EXPECT_FALSE(parser->KeepAlive());
}

TEST_F(Given_MessageParser, When_EofPrecedesAnyInput_Then_TruncationIsReportedWithoutAssertion)
{
    auto parser = Create();

    EXPECT_THROW(parser->Finish(), http::MessageError);

    EXPECT_FALSE(parser->Complete());
}

TEST_F(Given_MessageParser, When_HeaderLimitIsExceeded_Then_MessageIsRejected)
{
    auto parser = Create(http::ParserOptions{.HeaderLimit = 32});
    const std::string input = "GET / HTTP/1.1\r\nX-Long: " + std::string(64, 'a') + "\r\n\r\n";

    EXPECT_THROW((void)parser->Put(Bytes(input), {}), http::MessageError);
}

TEST_F(Given_MessageParser, When_DeclaredBodyExceedsLimit_Then_MessageIsRejectedBeforeBody)
{
    auto parser = Create(http::ParserOptions{.BodyLimit = 3});
    const std::string input = "PUT / HTTP/1.1\r\nContent-Length: 4\r\n\r\n";

    EXPECT_THROW((void)parser->Put(Bytes(input), {}), http::MessageError);
}

TEST_P(Given_MessageParser, When_AmbiguousFramingIsReceived_Then_MessageIsRejected)
{
    auto parser = Create();
    const std::string input = std::string("PUT / HTTP/1.1\r\n") + GetParam() + "\r\n";

    EXPECT_THROW((void)parser->Put(Bytes(input), {}), http::MessageError);
}

INSTANTIATE_TEST_SUITE_P(Framing,
                         Given_MessageParser,
                         testing::Values("Content-Length: 4\r\nContent-Length: 5\r\n",
                                         "Content-Length: 4\r\nContent-Length: 4\r\n",
                                         "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
                                         "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n",
                                         "Content-Length: -1\r\n",
                                         "Content-Length: 4, 4\r\n",
                                         "Transfer-Encoding: gzip, chunked\r\n"));

TEST_F(Given_MessageParser, When_ChunkedResponseIsDecoded_Then_HeadersAndBodyAreReturned)
{
    const std::string encoded = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                                "Replay-Nonce: fake-nonce\r\n\r\n"
                                "4\r\ntest\r\n3\r\n123\r\n0\r\n\r\n";
    auto parser = Create({.Kind = http::MessageKind::Response});

    const tailgate::net::http::Response result = parser->DecodeResponse(encoded);

    EXPECT_EQ(result.Status(), 200);
    EXPECT_EQ(result.Headers().at("replay-nonce"), "fake-nonce");
    EXPECT_EQ(result.Body(), "test123");
}

TEST_F(Given_MessageParser, When_ChunkIsTruncated_Then_TypedFailureIsReturned)
{
    const std::string encoded =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\ntest\r\n";
    auto kind = tailgate::net::http::MessageErrorKind::InvalidState;
    auto parser = Create({.Kind = http::MessageKind::Response});

    try
    {
        (void)parser->DecodeResponse(encoded);
    }
    catch (const tailgate::net::http::MessageError& error)
    {
        kind = error.Kind();
    }

    EXPECT_EQ(kind, tailgate::net::http::MessageErrorKind::Truncated);
}

TEST_F(Given_MessageParser, When_InformationalResponsePrecedesFinal_Then_FinalBodyIsDecoded)
{
    const std::string encoded = "HTTP/1.1 100 Continue\r\n\r\n"
                                "HTTP/1.1 201 Created\r\nContent-Length: 4\r\n\r\ndata";
    auto parser = Create({.Kind = http::MessageKind::Response});

    const auto response = parser->DecodeResponse(encoded);

    EXPECT_EQ(response.Status(), 201);
    EXPECT_EQ(response.Body(), "data");
}

TEST_F(Given_MessageParser, When_NoResponseBytesArrive_Then_TruncationIsReported)
{
    auto parser = Create({.Kind = http::MessageKind::Response});

    EXPECT_THROW((void)parser->DecodeResponse(""), tailgate::net::http::MessageError);
}

TEST_F(Given_MessageParser, When_RequestParserDecodesResponse_Then_WrongMessageKindIsRejected)
{
    auto parser = Create();
    const std::string input = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    EXPECT_THROW((void)parser->DecodeResponse(input), http::MessageError);
}

TEST_F(Given_MessageParser, When_CompletedParserDecodesAgain_Then_StaleResponseIsNotReturned)
{
    auto parser = Create({.Kind = http::MessageKind::Response});
    const std::string input = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    ASSERT_EQ(parser->DecodeResponse(input).Status(), 200);

    EXPECT_THROW((void)parser->DecodeResponse(input), http::MessageError);
}

TEST_F(Given_MessageParser, When_InformationalResponsesExceedLimit_Then_DecodingIsRejected)
{
    auto parser = Create({.Kind = http::MessageKind::Response});
    std::string input;
    for (unsigned index = 0; index < 17; ++index)
    {
        input += "HTTP/1.1 103 Early Hints\r\n\r\n";
    }
    input += "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

    EXPECT_THROW((void)parser->DecodeResponse(input), http::MessageError);
}

TEST_F(Given_MessageParser, When_HeadResponseFollowsInterim_Then_SkipBodyOptionSurvivesReset)
{
    auto parser = Create({.Kind = http::MessageKind::Response, .SkipBody = true});
    const std::string input = "HTTP/1.1 103 Early Hints\r\n\r\n"
                              "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";

    const auto response = parser->DecodeResponse(input);

    EXPECT_EQ(response.Status(), 200);
    EXPECT_EQ(response.Headers().at("content-length"), "100");
    EXPECT_TRUE(response.Body().empty());
}

} // namespace tailgate::tests
