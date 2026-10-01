#include <condition_variable>
#include <future>
#include <mutex>
#include <system_error>

#include <gtest/gtest.h>

#include <tailgate/hosted/DerpAuthenticator.h>

#include "fakes/hosted/ActiveServerSession.h"

namespace
{

class ChallengeWriter final : public tailgate::hosted::ServerWriter
{
public:
    void Run(tailgate::hosted::ServerSession&,
             tailgate::base::ByteStream&,
             std::mutex&,
             const std::atomic<bool>&) override
    {
        ADD_FAILURE();
    }

    void Wake() noexcept override
    {
    }

    void Post(tailgate::hosted::Frame frame) override
    {
        {
            std::lock_guard lock(Mutex);
            Challenge = tailgate::hosted::ProtocolCodec::DecodeDerpChallenge(frame.Payload());
        }
        Changed.notify_all();
    }

    tailgate::hosted::DerpAuthenticationChallenge WaitForChallenge()
    {
        std::unique_lock lock(Mutex);
        Changed.wait(lock,
                     [&]
                     {
                         return Challenge.has_value();
                     });
        return *Challenge;
    }

    std::mutex Mutex;
    std::condition_variable Changed;
    std::optional<tailgate::hosted::DerpAuthenticationChallenge> Challenge;
};

class Given_HostedDerpAuthenticator : public testing::Test
{
protected:
    tailgate::tests::fakes::ActiveServerSession Active;
    ChallengeWriter Writer;
    tailgate::hosted::DerpAuthenticator Authenticator{*Active.Session, Writer};
};

} // namespace

TEST_F(Given_HostedDerpAuthenticator, When_ResponseArrives_Then_WaitingDialReceivesItsEnvelope)
{
    const std::vector<std::uint8_t> envelope{1, 2, 3};
    auto result = std::async(std::launch::async,
                             [&]
                             {
                                 return Authenticator.Authenticate({}, {});
                             });
    const auto challenge = Writer.WaitForChallenge();

    Authenticator.AcceptResponse(
        tailgate::hosted::DerpAuthenticationResponse(challenge.RequestId(), envelope));
    const auto received = result.get();

    EXPECT_EQ(received, envelope);
}

TEST_F(Given_HostedDerpAuthenticator, When_DialIsCancelled_Then_WaitEndsWithoutRemoteResponse)
{
    std::stop_source cancellation;
    auto result = std::async(std::launch::async,
                             [&]
                             {
                                 try
                                 {
                                     (void)Authenticator.Authenticate({}, cancellation.get_token());
                                 }
                                 catch (const std::system_error& error)
                                 {
                                     return error.code();
                                 }
                                 return std::error_code{};
                             });
    const auto challenge = Writer.WaitForChallenge();

    cancellation.request_stop();
    const auto error = result.get();
    Authenticator.AcceptResponse(
        tailgate::hosted::DerpAuthenticationResponse(challenge.RequestId(), {1}));

    EXPECT_EQ(error, std::errc::operation_canceled);
}
