#include <atomic>
#include <chrono>
#include <mutex>

#include <gtest/gtest.h>

#include <tailgate/hosted/Pump.h>
#include <tailgate/hosted/ServerWriter.h>

#include "fakes/base/FakeByteStream.h"
#include "fakes/hosted/ActiveServerSession.h"

namespace tailgate::tests
{
namespace
{

class WriterEventLoop final : public base::EventLoop
{
public:
    explicit WriterEventLoop(base::TimeProvider& time) : m_time(time)
    {
    }

    base::EventWaitResult Wait(std::size_t) override
    {
        ADD_FAILURE() << "Writer must wait on a deadline";
        return Result();
    }

    base::EventWaitResult Wait(const base::WaitToken& token, std::size_t) override
    {
        ++WaitCalls;
        dynamic_cast<fakes::FakeTimeProvider&>(m_time).Advance(AdvanceBy);
        DeadlineReached = dynamic_cast<const fakes::FakeWaitToken&>(token).IsSignaled();
        return Result();
    }

    void Wake() noexcept override
    {
        ++WakeCalls;
    }

    base::EventWaitResult Result() const
    {
        return base::EventWaitResult{
            .Status = base::EventWaitStatus::Events,
            .Events = {base::Event{.Token = base::EventToken{.Value = 1}, .Readiness = Readiness}}};
    }

    base::TimeProvider::Duration AdvanceBy{};
    base::EventReadiness Readiness = base::EventReadiness::Closed;
    bool DeadlineReached = false;
    std::size_t WaitCalls = 0;
    std::size_t WakeCalls = 0;

private:
    base::TimeProvider& m_time;
};

} // namespace

class Given_HostedServerWriter : public testing::Test
{
protected:
    Given_HostedServerWriter()
    {
        active.Injector.InstallSingleton<WriterEventLoop, base::EventLoop>();
    }

    fakes::ActiveServerSession active;
    fakes::FakeByteStream stream{"writer"};
    std::mutex streamMutex;
    std::atomic<bool> stopping = false;
};

TEST_F(Given_HostedServerWriter, When_PumpIsDueBeforeHeartbeat_Then_WaitUsesPumpDeadline)
{
    auto& loop = active.Injector.create<WriterEventLoop&>();
    loop.AdvanceBy = std::chrono::milliseconds(100);
    (void)active.Session->Process(hosted::EncodePumpSchedule(
        hosted::PumpSchedule{.RequestId = 1, .Delay = std::chrono::milliseconds(100)}));
    auto& writer = active.Injector.create<hosted::ServerWriter&>();

    writer.Run(*active.Session, stream, streamMutex, stopping);
    hosted::Decoder decoder;
    decoder.Feed(stream.Written);
    const auto reply = decoder.Next();
    const auto requestId = reply ? hosted::TryDecodePumpReply(reply->Payload()) : std::nullopt;
    const auto extra = decoder.Next();
    ASSERT_TRUE(reply);

    EXPECT_TRUE(loop.DeadlineReached);
    EXPECT_EQ(reply->Type(), hosted::MessageType::Pump);
    EXPECT_EQ(requestId, 1U);
    EXPECT_FALSE(extra.has_value());
}

TEST_F(Given_HostedServerWriter, When_PacketsAreReady_Then_DuePumpIsNotStarved)
{
    auto& loop = active.Injector.create<WriterEventLoop&>();
    loop.Readiness = base::EventReadiness::Readable | base::EventReadiness::Closed;
    auto& device = active.Injector.create<fakes::FakeDevice&>();
    const auto peerPacket = hosted::ProtocolCodec::EncodePeerPacket(
        hosted::PeerPacket(active.ClientPublicKey, {1, 2, 3, 4}));
    device.Incoming.push_back(wgengine::tstun::DeviceReadResult{
        .Result = wgengine::tstun::DeviceIoResult::Complete, .Packet = peerPacket});
    (void)active.Session->Process(hosted::EncodePumpSchedule(
        hosted::PumpSchedule{.RequestId = 1, .Delay = std::chrono::milliseconds::zero()}));
    auto& writer = active.Injector.create<hosted::ServerWriter&>();

    writer.Run(*active.Session, stream, streamMutex, stopping);
    hosted::Decoder decoder;
    decoder.Feed(stream.Written);
    const auto first = decoder.Next();
    const auto second = decoder.Next();
    ASSERT_TRUE(first);
    ASSERT_TRUE(second);

    EXPECT_EQ(first->Type(), hosted::MessageType::Pump);
    EXPECT_EQ(second->Type(), hosted::MessageType::ServerPacket);
    EXPECT_EQ(second->Payload(), peerPacket);
    EXPECT_TRUE(device.Closed);
}

TEST_F(Given_HostedServerWriter, When_DeviceClosesWithoutReadableEvent_Then_WriterExits)
{
    auto& loop = active.Injector.create<WriterEventLoop&>();
    auto& writer = active.Injector.create<hosted::ServerWriter&>();

    writer.Run(*active.Session, stream, streamMutex, stopping);

    EXPECT_EQ(loop.WaitCalls, 1U);
    EXPECT_TRUE(stream.Written.empty());
    EXPECT_TRUE(active.Injector.create<fakes::FakeDevice&>().Closed);
}

TEST_F(Given_HostedServerWriter, When_IdleDeadlinePasses_Then_HeartbeatRemainsAvailable)
{
    auto& loop = active.Injector.create<WriterEventLoop&>();
    loop.AdvanceBy = std::chrono::seconds(20);
    auto& writer = active.Injector.create<hosted::ServerWriter&>();

    writer.Run(*active.Session, stream, streamMutex, stopping);
    hosted::Decoder decoder;
    decoder.Feed(stream.Written);
    const auto reply = decoder.Next();
    ASSERT_TRUE(reply);

    EXPECT_TRUE(loop.DeadlineReached);
    EXPECT_EQ(reply->Type(), hosted::MessageType::Heartbeat);
}

TEST_F(Given_HostedServerWriter, When_ScheduleChanges_Then_WriterCanBeWoken)
{
    auto& writer = active.Injector.create<hosted::ServerWriter&>();

    writer.Wake();

    EXPECT_EQ(active.Injector.create<WriterEventLoop&>().WakeCalls, 1U);
}

} // namespace tailgate::tests
