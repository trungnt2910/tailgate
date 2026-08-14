#include <gtest/gtest.h>

#include <tailgate/derp/SendQueue.h>

TEST(Given_QueuedDerpData, When_ControlArrives_Then_ControlIsSentFirst)
{
    tailgate::derp::DerpSendQueue queue(4, 64);
    EXPECT_TRUE(
        queue.Push({.Payload = {1}}, tailgate::derp::DerpSendQueue::Priority::Data).Accepted);
    EXPECT_TRUE(
        queue.Push({.Payload = {2}}, tailgate::derp::DerpSendQueue::Priority::Control).Accepted);

    const auto first = queue.Pop();
    const auto second = queue.Pop();

    EXPECT_TRUE(first.has_value());
    EXPECT_EQ(std::vector<std::uint8_t>({2}), first->Payload);
    EXPECT_TRUE(second.has_value());
    EXPECT_EQ(std::vector<std::uint8_t>({1}), second->Payload);
}

TEST(Given_FullDerpQueue, When_ControlArrives_Then_OldestDataIsDropped)
{
    tailgate::derp::DerpSendQueue queue(2, 64);
    EXPECT_TRUE(
        queue.Push({.Payload = {1}}, tailgate::derp::DerpSendQueue::Priority::Data).Accepted);
    EXPECT_TRUE(
        queue.Push({.Payload = {2}}, tailgate::derp::DerpSendQueue::Priority::Data).Accepted);

    const auto pushed =
        queue.Push({.Payload = {3}}, tailgate::derp::DerpSendQueue::Priority::Control);
    const auto first = queue.Pop();
    const auto second = queue.Pop();

    EXPECT_TRUE(pushed.Accepted);
    EXPECT_EQ(1U, pushed.DroppedPackets);
    EXPECT_TRUE(first.has_value());
    EXPECT_EQ(std::vector<std::uint8_t>({3}), first->Payload);
    EXPECT_TRUE(second.has_value());
    EXPECT_EQ(std::vector<std::uint8_t>({2}), second->Payload);
}

TEST(Given_OversizedDerpPacket, When_Queued_Then_ItIsRejected)
{
    tailgate::derp::DerpSendQueue queue(2, 2);

    const auto pushed =
        queue.Push({.Payload = {1, 2, 3}}, tailgate::derp::DerpSendQueue::Priority::Data);

    EXPECT_FALSE(pushed.Accepted);
    EXPECT_EQ(0U, queue.Size());
    EXPECT_EQ(0U, queue.Bytes());
}
