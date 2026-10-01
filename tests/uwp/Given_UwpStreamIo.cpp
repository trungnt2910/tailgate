#include <algorithm>
#include <atomic>
#include <future>
#include <system_error>
#include <vector>

#include <windows.h>

#include <gtest/gtest.h>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Storage.Streams.h>

#include "common/UwpStreamIo.h"
#include "fakes/base/FakeEventLoop.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace streams = winrt::Windows::Storage::Streams;
namespace foundation = winrt::Windows::Foundation;

class ControlledStreams : public winrt::implements<ControlledStreams,
                                                   streams::IInputStream,
                                                   streams::IOutputStream,
                                                   foundation::IClosable>
{
public:
    foundation::IAsyncOperationWithProgress<streams::IBuffer, std::uint32_t>
    ReadAsync(streams::IBuffer buffer, std::uint32_t maximumSize, streams::InputStreamOptions)
    {
        auto lifetime = get_strong();
        auto cancellation = co_await winrt::get_cancellation_token();
        cancellation.callback(
            [this]
            {
                SetEvent(ReadReady.get());
            });
        co_await winrt::resume_on_signal(ReadReady.get());
        if (cancellation())
        {
            throw winrt::hresult_canceled();
        }
        const auto count = std::min<std::size_t>(maximumSize, ReadBytes.size() - ReadOffset);
        std::copy_n(ReadBytes.begin() + ReadOffset, count, buffer.data());
        ReadOffset += count;
        buffer.Length(static_cast<std::uint32_t>(count));
        co_return buffer;
    }

    foundation::IAsyncOperationWithProgress<std::uint32_t, std::uint32_t>
    WriteAsync(streams::IBuffer buffer)
    {
        auto lifetime = get_strong();
        ++WriteCalls;
        Written.assign(buffer.data(), buffer.data() + buffer.Length());
        auto cancellation = co_await winrt::get_cancellation_token();
        cancellation.callback(
            [this]
            {
                SetEvent(WriteReady.get());
            });
        co_await winrt::resume_on_signal(WriteReady.get());
        if (cancellation())
        {
            throw winrt::hresult_canceled();
        }
        co_return buffer.Length();
    }

    foundation::IAsyncOperation<bool> FlushAsync()
    {
        co_return true;
    }

    void Close()
    {
        SetEvent(ReadReady.get());
        SetEvent(WriteReady.get());
    }

    winrt::handle ReadReady{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    winrt::handle WriteReady{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::vector<std::uint8_t> ReadBytes{42};
    std::size_t ReadOffset = 0;
    std::vector<std::uint8_t> Written;
    std::size_t WriteCalls = 0;
};

class ClosedStreams : public winrt::implements<ClosedStreams,
                                               streams::IInputStream,
                                               streams::IOutputStream,
                                               foundation::IClosable>
{
public:
    foundation::IAsyncOperationWithProgress<streams::IBuffer, std::uint32_t>
    ReadAsync(streams::IBuffer, std::uint32_t, streams::InputStreamOptions)
    {
        throw winrt::hresult_illegal_method_call();
    }

    foundation::IAsyncOperationWithProgress<std::uint32_t, std::uint32_t>
    WriteAsync(streams::IBuffer)
    {
        throw winrt::hresult_illegal_method_call();
    }

    foundation::IAsyncOperation<bool> FlushAsync()
    {
        throw winrt::hresult_illegal_method_call();
    }

    void Close()
    {
    }
};

class Given_UwpStreamIo : public testing::Test
{
protected:
    winrt::com_ptr<ControlledStreams> Streams = winrt::make_self<ControlledStreams>();
    tailgate::tests::fakes::FakeEventLoop Events;
    UwpStreamIo Io{
        Streams.as<streams::IInputStream>(),
        Streams.as<streams::IOutputStream>(),
        StreamIoOptions{.Timeout = std::chrono::seconds(5), .Events = Events, .Token = Token}};
    static constexpr base::EventToken Token{.Value = 77};
};

} // namespace

TEST_F(Given_UwpStreamIo, When_WriteIsPending_Then_ReturnsWouldBlockAndCompletesOnlyOnce)
{
    Io.SetNonBlocking(true);
    const std::vector<std::uint8_t> bytes{1, 2, 3};

    const auto first = Io.TryWriteSome(bytes.data(), bytes.size());
    const auto pending = Io.TryWriteSome(bytes.data(), bytes.size());
    SetEvent(Streams->WriteReady.get());
    Events.WaitForWake();
    const auto completed = Io.TryWriteSome(bytes.data(), bytes.size());
    const auto ready = Events.TakePostedEvents(1);
    ASSERT_EQ(ready.size(), 1U);

    EXPECT_FALSE(first);
    EXPECT_FALSE(pending);
    EXPECT_EQ(completed, bytes.size());
    EXPECT_EQ(Streams->WriteCalls, 1U);
    EXPECT_EQ(Streams->Written, bytes);
    EXPECT_EQ(ready.front().Token, Token);
    EXPECT_TRUE(base::HasReadiness(ready.front().Readiness, base::EventReadiness::Writable));
}

TEST_F(Given_UwpStreamIo, When_ReadCompletes_Then_IdleEventLoopIsNotified)
{
    Io.SetNonBlocking(true);

    const auto pending = Io.TryReadSome(1);
    SetEvent(Streams->ReadReady.get());
    Events.WaitForWake();
    const auto completed = Io.TryReadSome(1);
    const auto ready = Events.TakePostedEvents(1);
    ASSERT_EQ(ready.size(), 1U);

    EXPECT_FALSE(pending);
    EXPECT_EQ(completed, std::optional(std::vector<std::uint8_t>{42}));
    EXPECT_EQ(ready.front().Token, Token);
    EXPECT_TRUE(base::HasReadiness(ready.front().Readiness, base::EventReadiness::Readable));
}

TEST_F(Given_UwpStreamIo, When_ReadLimitShrinks_Then_PrefetchedBytesAreRetained)
{
    Streams->ReadBytes = {1, 2, 3, 4, 5};
    Io.SetNonBlocking(true);
    SetEvent(Streams->ReadReady.get());
    Events.WaitForWake();

    const auto first = Io.TryReadSome(4);
    Events.WaitForWake(2);
    const auto second = Io.TryReadSome(1);
    const bool buffered = Io.HasBufferedInput();
    const auto third = Io.TryReadSome(3);

    EXPECT_EQ(first, std::optional(std::vector<std::uint8_t>{1}));
    EXPECT_EQ(second, std::optional(std::vector<std::uint8_t>{2}));
    EXPECT_TRUE(buffered);
    EXPECT_EQ(third, std::optional(std::vector<std::uint8_t>{3, 4, 5}));
}

TEST_F(Given_UwpStreamIo, When_BlockingWriteIsCancelled_Then_WaitEndsWithoutPeerProgress)
{
    std::stop_source cancellation;
    UwpStreamIo io(Streams.as<streams::IInputStream>(),
                   Streams.as<streams::IOutputStream>(),
                   StreamIoOptions{.Timeout = std::chrono::seconds(5),
                                   .Cancellation = cancellation.get_token()});
    std::promise<void> started;
    auto result = std::async(std::launch::async,
                             [&]
                             {
                                 winrt::init_apartment(winrt::apartment_type::multi_threaded);
                                 const std::uint8_t byte = 1;
                                 started.set_value();
                                 bool cancelled = false;
                                 try
                                 {
                                     (void)io.TryWriteSome(&byte, 1);
                                 }
                                 catch (const winrt::hresult_canceled&)
                                 {
                                     cancelled = true;
                                 }
                                 winrt::uninit_apartment();
                                 return cancelled;
                             });
    started.get_future().wait();

    cancellation.request_stop();
    const bool cancelled = result.get();

    EXPECT_TRUE(cancelled);
}

TEST_F(Given_UwpStreamIo, When_StreamClosesWithPendingIo_Then_LateCompletionsCannotNotifyOwner)
{
    Io.SetNonBlocking(true);
    const std::uint8_t byte = 1;
    (void)Io.TryWriteSome(&byte, 1);

    Io.Close();
    Io.SetWriteInterest(true);
    const auto ready = Events.TakePostedEvents(2);

    EXPECT_TRUE(ready.empty());
    EXPECT_EQ(Events.WakeCalls(), 0U);
}

TEST_F(Given_UwpStreamIo, When_ReadFailsImmediately_Then_UsesSharedTransportErrorContract)
{
    const auto closed = winrt::make_self<ClosedStreams>();
    UwpStreamIo io(closed.as<streams::IInputStream>(), closed.as<streams::IOutputStream>(), {});

    EXPECT_THROW((void)io.TryReadSome(1), std::system_error);
}

TEST_F(Given_UwpStreamIo, When_WriteFailsImmediately_Then_UsesSharedTransportErrorContract)
{
    const auto closed = winrt::make_self<ClosedStreams>();
    UwpStreamIo io(closed.as<streams::IInputStream>(), closed.as<streams::IOutputStream>(), {});
    const std::uint8_t byte = 1;

    EXPECT_THROW((void)io.TryWriteSome(&byte, 1), std::system_error);
}

} // namespace tailgate::uwp::tests
