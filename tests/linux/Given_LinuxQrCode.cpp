#include <algorithm>
#include <string>

#include <gtest/gtest.h>

#include "LinuxQrCode.h"

TEST(Given_Utf8Locale, When_ResolvingAutomaticQrFormat_Then_CompactUnicodeIsUsed)
{
    const auto format = tailgate::linux_frontend::ResolveQrTextFormat("auto", "en_US.UTF-8");

    EXPECT_EQ(format, tailgate::linux_frontend::QrTextFormat::Small);
}

TEST(Given_LegacyLocale, When_ResolvingAutomaticQrFormat_Then_AsciiIsUsed)
{
    const auto format = tailgate::linux_frontend::ResolveQrTextFormat("auto", "C");

    EXPECT_EQ(format, tailgate::linux_frontend::QrTextFormat::Ascii);
}

TEST(Given_QrCode, When_RenderingAscii_Then_QuietZoneAndFinderPatternArePresent)
{
    const tailgate::qr::QrCode code = tailgate::qr::EncodeQrCode("Tailgate");

    const std::string rendered =
        tailgate::linux_frontend::RenderQrCode(code, tailgate::linux_frontend::QrTextFormat::Ascii);
    const std::size_t firstDark = rendered.find("##");
    const std::size_t lineWidth = static_cast<std::size_t>((code.Size + 8) * 2 + 1);

    EXPECT_EQ(firstDark, lineWidth * 4 + 8);
    EXPECT_TRUE(rendered.ends_with('\n'));
}

TEST(Given_QrCode, When_RenderingSmall_Then_RowsArePacked)
{
    const tailgate::qr::QrCode code = tailgate::qr::EncodeQrCode("Tailgate");

    const std::string rendered =
        tailgate::linux_frontend::RenderQrCode(code, tailgate::linux_frontend::QrTextFormat::Small);
    const std::size_t rows =
        static_cast<std::size_t>(std::count(rendered.begin(), rendered.end(), '\n'));

    EXPECT_EQ(rows, static_cast<std::size_t>((code.Size + 8 + 1) / 2));
    EXPECT_NE(rendered.find("█"), std::string::npos);
}
