#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/control/base/H2.h>

#include "MapStreamResponse.h"

TEST(Given_MapStreamResponse, When_HttpErrorStreamEnds_Then_RejectionIsReported)
{
    tailgate::control::client::MapStreamResponse response;
    response.Start(3);
    response.ReceiveHeaders(tailgate::control::base::H2Headers{{":status", "500"}});
    response.ReceiveData(std::vector<std::uint8_t>{'f', 'a', 'i', 'l', 'e', 'd'});

    const auto finish = [&response]()
    {
        response.Finish();
    };

    EXPECT_THROW(finish(), tailgate::control::client::MapStreamRejected);
}

TEST(Given_MapStreamResponse, When_SuccessfulStreamEnds_Then_ClosureIsReported)
{
    tailgate::control::client::MapStreamResponse response;
    response.Start(3);
    response.ReceiveHeaders(tailgate::control::base::H2Headers{{":status", "200"}});

    const auto finish = [&response]()
    {
        response.Finish();
    };

    EXPECT_THROW(finish(), std::runtime_error);
}
