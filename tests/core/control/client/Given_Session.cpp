#include <memory>

#include <gtest/gtest.h>

#include "impl/SessionImpl.h"

#include "fakes/types/nettype/FakeTcpSocket.h"

namespace tailgate::tests
{
namespace
{

using control::client::impl::SessionImpl;
using fakes::FakeTcpSocket;
using fakes::FakeTcpSocketState;

TEST(Given_Session, When_Closed_Then_SocketIsCancelledButRetainedUntilDestruction)
{
    auto state = std::make_shared<FakeTcpSocketState>();
    auto subject = std::make_unique<SessionImpl>(std::make_unique<FakeTcpSocket>(state), nullptr);

    subject->Close();
    const bool closedBeforeDestruction = state->Closed;
    const bool retainedAfterClose = !state->Destroyed;
    subject.reset();

    EXPECT_TRUE(closedBeforeDestruction);
    EXPECT_TRUE(retainedAfterClose);
    EXPECT_TRUE(state->Destroyed);
    EXPECT_EQ(state->CloseCalls, 1U);
}

TEST(Given_Session, When_CloseIsRepeated_Then_TransportCancellationIsIdempotent)
{
    auto state = std::make_shared<FakeTcpSocketState>();
    SessionImpl subject(std::make_unique<FakeTcpSocket>(state), nullptr);

    subject.Close();
    subject.Close();

    EXPECT_EQ(state->CloseCalls, 1U);
    EXPECT_FALSE(state->Destroyed);
}

TEST(Given_Session, When_DestroyedWithoutClose_Then_TransportIsClosedAndReleased)
{
    auto state = std::make_shared<FakeTcpSocketState>();
    auto subject = std::make_unique<SessionImpl>(std::make_unique<FakeTcpSocket>(state), nullptr);

    subject.reset();

    EXPECT_TRUE(state->Closed);
    EXPECT_TRUE(state->Destroyed);
    EXPECT_EQ(state->CloseCalls, 1U);
}

} // namespace
} // namespace tailgate::tests
