#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/hosted/Pump.h>

namespace tailgate::tests
{

TEST(Given_PumpCodec, When_ScheduleIsEncoded_Then_HostedFrameRoundTrips)
{
    const hosted::PumpSchedule schedule{.RequestId = std::numeric_limits<std::uint64_t>::max(),
                                        .Delay = std::chrono::milliseconds(250)};
    hosted::Decoder decoder;

    const auto encoded = hosted::EncodePumpSchedule(schedule).Encode();
    decoder.Feed(encoded);
    const auto frame = decoder.Next();
    const auto decoded = frame ? hosted::TryDecodePumpSchedule(frame->Payload()) : std::nullopt;
    ASSERT_TRUE(frame);
    ASSERT_TRUE(decoded);

    EXPECT_EQ(frame->Type(), hosted::MessageType::PumpSchedule);
    EXPECT_EQ(decoded->RequestId, schedule.RequestId);
    EXPECT_EQ(decoded->Delay, schedule.Delay);
}

TEST(Given_PumpCodec, When_CancellationIsEncoded_Then_ItIsNotAnImmediateRequest)
{
    const hosted::PumpSchedule schedule{.RequestId = 42, .Delay = std::nullopt};

    const auto frame = hosted::EncodePumpSchedule(schedule);
    const auto decoded = hosted::TryDecodePumpSchedule(frame.Payload());
    ASSERT_TRUE(decoded);

    EXPECT_EQ(decoded->RequestId, 42U);
    EXPECT_FALSE(decoded->Delay.has_value());
}

TEST(Given_PumpCodec, When_ReplyIsEncoded_Then_HostedFrameRoundTrips)
{
    hosted::Decoder decoder;
    const auto source = hosted::EncodePumpReply(42).Encode();

    decoder.Feed(source);
    const auto frame = decoder.Next();
    const auto requestId = frame ? hosted::TryDecodePumpReply(frame->Payload()) : std::nullopt;
    ASSERT_TRUE(frame);

    EXPECT_EQ(frame->Type(), hosted::MessageType::Pump);
    EXPECT_EQ(requestId, 42U);
}

TEST(Given_PumpCodec, When_ScheduleHasInvalidLengthOrId_Then_DecodingFails)
{
    const std::array<std::vector<std::uint8_t>, 4> payloads{std::vector<std::uint8_t>{},
                                                            std::vector<std::uint8_t>(11),
                                                            std::vector<std::uint8_t>(12),
                                                            std::vector<std::uint8_t>(13)};

    std::array<bool, payloads.size()> accepted{};
    for (std::size_t index = 0; index < payloads.size(); ++index)
    {
        accepted[index] = hosted::TryDecodePumpSchedule(payloads[index]).has_value();
    }

    EXPECT_EQ(accepted, (std::array<bool, payloads.size()>{}));
}

TEST(Given_PumpCodec, When_DelayExceedsBound_Then_DecodingFails)
{
    auto payload = hosted::EncodePumpSchedule(
                       hosted::PumpSchedule{.RequestId = 1, .Delay = hosted::MaximumPumpDelay})
                       .Payload();
    ++payload.back();

    const auto decoded = hosted::TryDecodePumpSchedule(payload);

    EXPECT_FALSE(decoded.has_value());
}

TEST(Given_PumpCodec, When_ReplyIsMissingOrHasZeroId_Then_DecodingFails)
{
    const std::array<std::uint8_t, sizeof(std::uint64_t)> zero{};

    const auto empty = hosted::TryDecodePumpReply({});
    const auto invalidId = hosted::TryDecodePumpReply(zero);

    EXPECT_FALSE(empty.has_value());
    EXPECT_FALSE(invalidId.has_value());
}

} // namespace tailgate::tests
