#include <string>

#include <gtest/gtest.h>

#include <tailgate/net/http/Client.h>

TEST(Given_HttpCodec, When_HttpsRequestIsEncoded_Then_TargetAndHeadersArePreserved)
{
    const tailgate::net::http::Request request("POST",
                                               "https://acme.example.com:8443/order/1",
                                               {{"content-type", "application/json"}},
                                               "{}");

    const tailgate::net::http::HttpsUrl url = tailgate::net::http::HttpsUrl::Parse(request.Url());
    const std::string encoded = request.Encode();

    EXPECT_EQ(url.Host(), "acme.example.com");
    EXPECT_EQ(url.Service(), "8443");
    EXPECT_EQ(url.Path(), "/order/1");
    EXPECT_NE(encoded.find("POST /order/1 HTTP/1.1\r\n"), std::string::npos);
    EXPECT_NE(encoded.find("Host: acme.example.com\r\n"), std::string::npos);
    EXPECT_NE(encoded.find("content-type: application/json\r\n"), std::string::npos);
    EXPECT_TRUE(encoded.ends_with("\r\n\r\n{}"));
}

TEST(Given_HttpCodec, When_ChunkedResponseIsDecoded_Then_HeadersAndBodyAreReturned)
{
    const std::string encoded = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                                "Replay-Nonce: fake-nonce\r\n\r\n"
                                "4\r\ntest\r\n3\r\n123\r\n0\r\n\r\n";

    const tailgate::net::http::Response result = tailgate::net::http::Response::Decode(encoded);

    EXPECT_EQ(result.Status(), 200);
    EXPECT_EQ(result.Headers().at("replay-nonce"), "fake-nonce");
    EXPECT_EQ(result.Body(), "test123");
}

TEST(Given_HttpCodec, When_ChunkIsTruncated_Then_TypedFailureIsReturned)
{
    const std::string encoded =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\ntest\r\n";
    tailgate::net::http::CodecErrorKind kind = tailgate::net::http::CodecErrorKind::InvalidUrl;

    try
    {
        (void)tailgate::net::http::Response::Decode(encoded);
    }
    catch (const tailgate::net::http::CodecError& error)
    {
        kind = error.Kind();
    }

    EXPECT_EQ(kind, tailgate::net::http::CodecErrorKind::TruncatedChunk);
}
