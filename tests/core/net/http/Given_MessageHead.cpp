#include <string>

#include <gtest/gtest.h>

#include <tailgate/net/http/Message.h>

namespace tailgate::tests
{
namespace http = net::http;

TEST(Given_MessageHead, When_StreamingPutIsEncoded_Then_BodyLengthIsNotInferred)
{
    http::MessageHead head;
    head.Method("PUT");
    head.Target("/docs/a");
    head.Fields({{"Host", "example.com"}, {"Content-Length", "10000000000"}});

    const auto encoded = head.Encode();

    EXPECT_EQ(encoded,
              "PUT /docs/a HTTP/1.1\r\nHost: example.com\r\n"
              "Content-Length: 10000000000\r\n\r\n");
}

TEST(Given_ChunkEncoder, When_ChunksAreEncoded_Then_FinalChunkIsExplicit)
{
    const std::string body = "data";
    const auto bytes = std::span(reinterpret_cast<const std::uint8_t*>(body.data()), body.size());

    const auto chunk = http::ChunkEncoder::Encode(bytes);
    const auto empty = http::ChunkEncoder::Encode({});
    const auto last = http::ChunkEncoder::EncodeLast();

    EXPECT_EQ(chunk, "4\r\ndata\r\n");
    EXPECT_TRUE(empty.empty());
    EXPECT_EQ(last, "0\r\n\r\n");
}

TEST(Given_MessageHead, When_HeaderValueContainsNewline_Then_InjectionIsRejected)
{
    http::MessageHead head;
    head.Method("GET");
    head.Target("/");
    head.Fields({{"Host", "example.com\r\nInjected: yes"}});

    EXPECT_THROW((void)head.Encode(), http::MessageError);
}

TEST(Given_MessageHead, When_LengthAndChunkingAreBothSupplied_Then_FramingIsRejected)
{
    http::MessageHead head;
    head.Method("PUT");
    head.Target("/");
    head.Fields({{"Content-Length", "5"}, {"Transfer-Encoding", "chunked"}});

    EXPECT_THROW((void)head.Encode(), http::MessageError);
}

TEST(Given_HeaderField, When_NameHasMixedCase_Then_MatchingIsCaseInsensitive)
{
    const http::HeaderField field("cOnTeNt-LeNgTh", "42");

    const bool matches = field.HasName("Content-Length");
    const bool differs = field.HasName("Content-Type");

    EXPECT_TRUE(matches);
    EXPECT_FALSE(differs);
    EXPECT_EQ(field.Value(), "42");
}

TEST(Given_MessageHead, When_SingleFieldHasDuplicateSpellings_Then_AmbiguityIsRejected)
{
    http::MessageHead head;
    head.Fields({{"Host", "example.com"}, {"host", "example.ts.net"}});

    EXPECT_THROW((void)head.SingleField("Host"), http::MessageError);
}

TEST(Given_MessageHead, When_HopByHopFieldsAreRemoved_Then_NominatedFieldsAreRemovedToo)
{
    http::MessageHead head;
    head.Fields({{"Connection", " keep-alive, X-Private "},
                 {"x-private", "secret"},
                 {"Keep-Alive", "timeout=5"},
                 {"If-Match", "\"version\""}});

    head.RemoveHopByHopFields();

    EXPECT_EQ(head.Fields().size(), 1U);
    EXPECT_EQ(head.SingleField("If-Match"), "\"version\"");
    EXPECT_FALSE(head.SingleField("Connection"));
    EXPECT_FALSE(head.SingleField("X-Private"));
}

} // namespace tailgate::tests
