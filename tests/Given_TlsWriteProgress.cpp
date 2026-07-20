#include "TlsWriteProgress.h"

#include <gtest/gtest.h>

TEST(Given_TlsWriteNeedsPostHandshakeInput, When_InputProgresses_Then_WriteCompletes)
{
    constexpr int wantRead = -1;
    constexpr int written = 42;
    std::uint64_t readGeneration = 0;
    int calls = 0;

    const int result = tailgate::protocol::detail::WriteWithReadProgress(
        [&]()
        {
            ++calls;
            if (calls == 2)
            {
                ++readGeneration;
            }
            return calls < 3 ? wantRead : written;
        },
        wantRead,
        readGeneration);

    EXPECT_EQ(result, written);
    EXPECT_EQ(calls, 3);
    EXPECT_EQ(readGeneration, 1U);
}

TEST(Given_TlsWriteNeedsInput, When_TransportWouldBlock_Then_WriteRemainsPending)
{
    constexpr int wantRead = -1;
    std::uint64_t readGeneration = 0;
    int calls = 0;

    const int result = tailgate::protocol::detail::WriteWithReadProgress(
        [&]()
        {
            ++calls;
            return wantRead;
        },
        wantRead,
        readGeneration);

    EXPECT_EQ(result, wantRead);
    EXPECT_EQ(calls, 2);
    EXPECT_EQ(readGeneration, 0U);
}
