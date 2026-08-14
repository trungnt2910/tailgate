#include <algorithm>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/protocol/Noise.h>

TEST(Given_NoiseInitiator, When_WritingMessage1_Then_FrameShapeMatchesTs2021)
{
    tailgate::protocol::Bytes32 machinePrivate{};
    tailgate::protocol::Bytes32 ephemeralPrivate{};
    machinePrivate[0] = 1;
    ephemeralPrivate[0] = 2;

    tailgate::protocol::NoiseInitiator noise(machinePrivate, ephemeralPrivate);
    const std::vector<std::uint8_t> message = noise.WriteMessage1();
    const std::vector<std::uint8_t> prefix(
        message.begin(), message.begin() + std::min(message.size(), std::size_t{5}));

    EXPECT_EQ(message.size(), 101U);
    EXPECT_EQ(prefix, (std::vector<std::uint8_t>{0, 131, 1, 0, 96}));
}
