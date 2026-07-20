#include <gtest/gtest.h>

#include "tailgate/ByteStream.h"

#include <algorithm>
#include <deque>

namespace
{

class TryStream final : public tailgate::IByteStream
{
public:
    std::optional<std::size_t> TryWriteSome(const std::uint8_t* data, std::size_t size) override
    {
        const std::size_t written = std::min(size, MaximumWriteSize);
        Writes.insert(Writes.end(), data, data + written);
        return written;
    }

    std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t maxBytes) override
    {
        if (Reads.empty())
        {
            return std::nullopt;
        }
        std::vector<std::uint8_t> result = std::move(Reads.front());
        Reads.pop_front();
        if (result.size() > maxBytes)
        {
            throw std::runtime_error("test read exceeds requested capacity");
        }
        return result;
    }

    std::size_t MaximumWriteSize = 2;
    std::vector<std::uint8_t> Writes;
    std::deque<std::vector<std::uint8_t>> Reads;
};

} // namespace

TEST(Given_PartialTryOperations, When_UsingThrowingWrappers_Then_TryPrimitivesDriveIo)
{
    TryStream stream;
    stream.Reads.push_back({1, 2});
    stream.Reads.push_back({3, 4});
    const std::vector<std::uint8_t> output{5, 6, 7, 8};

    stream.WriteAll(output);
    const std::vector<std::uint8_t> input = stream.ReadExact(4);

    EXPECT_EQ(stream.Writes, output);
    EXPECT_EQ(input, (std::vector<std::uint8_t>{1, 2, 3, 4}));
}

TEST(Given_TryReadWouldBlock, When_UsingReadSome_Then_WrapperReportsWouldBlock)
{
    TryStream stream;

    const auto read = [&]()
    {
        (void)stream.ReadSome(1);
    };

    EXPECT_THROW(read(), tailgate::StreamWouldBlock);
}
