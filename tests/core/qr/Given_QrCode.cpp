#include <algorithm>
#include <stdexcept>

#include <gtest/gtest.h>

#include <tailgate/qr/QrCode.h>

TEST(Given_QrCode, When_ReadingFinderPattern_Then_ExpectedModulesArePresent)
{
    const tailgate::qr::QrCode code = tailgate::qr::QrCode::Encode("Tailgate");

    const bool topLeftCorner = code.Module(0, 0);
    const bool topLeftInnerBorder = code.Module(1, 1);
    const bool topLeftCenter = code.Module(3, 3);

    EXPECT_TRUE(topLeftCorner);
    EXPECT_FALSE(topLeftInnerBorder);
    EXPECT_TRUE(topLeftCenter);
}

TEST(Given_QrCode, When_ReadingOutsideMatrix_Then_AccessIsRejected)
{
    const tailgate::qr::QrCode code = tailgate::qr::QrCode::Encode("Tailgate");
    const auto readOutside = [&]()
    {
        (void)code.Module(code.Size(), 0);
    };

    EXPECT_THROW(readOutside(), std::out_of_range);
}

TEST(Given_QrCode, When_EncodingEmptyText_Then_InputIsRejected)
{
    const auto encode = []()
    {
        (void)tailgate::qr::QrCode::Encode("");
    };

    EXPECT_THROW(encode(), std::invalid_argument);
}

TEST(Given_QrCode, When_EncodingLoginUrl_Then_SquareModuleMatrixIsReturned)
{
    const tailgate::qr::QrCode code =
        tailgate::qr::QrCode::Encode("https://login.tailscale.com/a/fake-login-code");

    std::size_t darkModules = 0;
    for (int y = 0; y < code.Size(); ++y)
    {
        for (int x = 0; x < code.Size(); ++x)
        {
            darkModules += code.Module(x, y) ? 1U : 0U;
        }
    }

    EXPECT_GT(code.Size(), 0);
    EXPECT_GT(darkModules, 0U);
    EXPECT_LT(darkModules, static_cast<std::size_t>(code.Size() * code.Size()));
}
