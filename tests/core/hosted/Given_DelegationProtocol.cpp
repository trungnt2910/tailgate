#include <gtest/gtest.h>

#include <tailgate/hosted/Delegation.h>

namespace tailgate::hosted
{
namespace
{

class Given_DelegationProtocol : public testing::Test
{
protected:
    DelegationRequest Request{.Generation = 3,
                              .RequestId = 17,
                              .MapRevision = 9,
                              .Action = DelegationAction::Release,
                              .Regions = {1, 255, 65535}};
};

TEST_F(Given_DelegationProtocol, When_RequestIsEncoded_Then_AllOwnershipFieldsRoundTrip)
{
    const auto decoded = DecodeDelegationRequest(EncodeDelegation(Request));

    EXPECT_EQ(decoded, Request);
}

TEST_F(Given_DelegationProtocol, When_RequestIsTruncated_Then_DecoderRejectsIt)
{
    auto bytes = EncodeDelegation(Request).Payload();
    bytes.pop_back();

    const auto decoded = DecodeDelegationRequest(Frame(MessageType::Delegation, bytes));

    EXPECT_FALSE(decoded);
}

TEST_F(Given_DelegationProtocol, When_RegionsAreDuplicated_Then_EncoderRejectsAmbiguousOwnership)
{
    Request.Regions = {1, 1};

    EXPECT_THROW((void)EncodeDelegation(Request), std::invalid_argument);
}

TEST_F(Given_DelegationProtocol, When_WireRegionsAreOutOfOrder_Then_DecoderRejectsRequest)
{
    auto bytes = EncodeDelegation(Request).Payload();
    std::swap(bytes[26], bytes[30]);
    std::swap(bytes[27], bytes[31]);

    const auto decoded = DecodeDelegationRequest(Frame(MessageType::Delegation, bytes));

    EXPECT_FALSE(decoded);
}

TEST_F(Given_DelegationProtocol, When_GenerationIsZero_Then_EncoderRejectsRequest)
{
    Request.Generation = 0;

    EXPECT_THROW((void)EncodeDelegation(Request), std::invalid_argument);
}

TEST_F(Given_DelegationProtocol, When_FailureReplyIsEncoded_Then_TypedCauseRoundTrips)
{
    DelegationReply reply{.Generation = 2,
                          .RequestId = 5,
                          .MapRevision = 9,
                          .Status = DelegationStatus::Failed,
                          .Failure = DelegationFailure::StaleMap};

    const auto decoded = DecodeDelegationReply(EncodeDelegation(reply));

    EXPECT_EQ(decoded, reply);
}

TEST_F(Given_DelegationProtocol, When_SuccessHasFailureReason_Then_EncoderRejectsInconsistentReply)
{
    DelegationReply reply{.Generation = 2,
                          .RequestId = 5,
                          .MapRevision = 9,
                          .Status = DelegationStatus::Released,
                          .Failure = DelegationFailure::StaleMap};

    EXPECT_THROW((void)EncodeDelegation(reply), std::invalid_argument);
}

TEST_F(Given_DelegationProtocol, When_MapAckIsEncoded_Then_RevisionRoundTrips)
{
    const auto decoded = DecodeMapAcknowledgement(EncodeMapAcknowledgement(512));

    EXPECT_EQ(decoded, 512U);
}

TEST_F(Given_DelegationProtocol, When_ZeroMapAckArrives_Then_DecoderRejectsIt)
{
    const auto decoded =
        DecodeMapAcknowledgement(Frame(MessageType::NetworkMapAck, std::vector<std::uint8_t>(8)));

    EXPECT_FALSE(decoded);
}

} // namespace

} // namespace tailgate::hosted
