#include <algorithm>
#include <stdexcept>

#include <gtest/gtest.h>

#include <tailgate/qr/QrCode.h>

TEST(Given_LoginUrl, When_EncodingQrCode_Then_SquareModuleMatrixIsReturned)
{
    const tailgate::qr::QrCode code =
        tailgate::qr::EncodeQrCode("https://login.tailscale.com/a/fake-login-code");

    const std::size_t darkModules =
        static_cast<std::size_t>(std::count(code.Modules.begin(), code.Modules.end(), 1));
    EXPECT_GT(code.Size, 0);
    EXPECT_EQ(code.Modules.size(), static_cast<std::size_t>(code.Size * code.Size));
    EXPECT_GT(darkModules, 0U);
    EXPECT_LT(darkModules, code.Modules.size());
}

TEST(Given_QrCode, When_ReadingFinderPattern_Then_ExpectedModulesArePresent)
{
    const tailgate::qr::QrCode code = tailgate::qr::EncodeQrCode("Tailgate");

    const bool topLeftCorner = code.Module(0, 0);
    const bool topLeftInnerBorder = code.Module(1, 1);
    const bool topLeftCenter = code.Module(3, 3);

    EXPECT_TRUE(topLeftCorner);
    EXPECT_FALSE(topLeftInnerBorder);
    EXPECT_TRUE(topLeftCenter);
}

TEST(Given_QrCode, When_ReadingOutsideMatrix_Then_AccessIsRejected)
{
    const tailgate::qr::QrCode code = tailgate::qr::EncodeQrCode("Tailgate");
    const auto readOutside = [&]()
    {
        (void)code.Module(code.Size, 0);
    };

    EXPECT_THROW(readOutside(), std::out_of_range);
}

TEST(Given_EmptyText, When_EncodingQrCode_Then_InputIsRejected)
{
    const auto encode = []()
    {
        (void)tailgate::qr::EncodeQrCode("");
    };

    EXPECT_THROW(encode(), std::invalid_argument);
}
