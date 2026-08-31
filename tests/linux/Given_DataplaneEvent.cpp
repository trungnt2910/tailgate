#include <cstdint>

#include <gtest/gtest.h>

#include "DataplaneEvents.h"

TEST(Given_DataplaneEvent, When_ConvertedToTokenAndBack_Then_KindAndIndexArePreserved)
{
    constexpr std::uint32_t index = 42;
    const tailgate::linux_frontend::DataplaneEvent source(
        tailgate::linux_frontend::DataplaneEvent::Kind::Derp, index);

    const tailgate::base::EventToken token = source.Token();
    const tailgate::linux_frontend::DataplaneEvent decoded =
        tailgate::linux_frontend::DataplaneEvent::FromValue(token.Value);

    EXPECT_EQ(decoded.Type(), tailgate::linux_frontend::DataplaneEvent::Kind::Derp);
    EXPECT_EQ(decoded.Index(), index);
}
