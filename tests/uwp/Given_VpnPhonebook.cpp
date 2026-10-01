#include <string>

#include <gtest/gtest.h>

#include "common/VpnPhonebook.h"

namespace
{

using tailgate::uwp::VpnPhonebook;

TEST(Given_VpnPhonebook, When_RepairingStoredProfile_Then_CommitsExactBytes)
{
    namespace storage = winrt::Windows::Storage;
    const auto folder = storage::ApplicationData::Current()
                            .TemporaryFolder()
                            .CreateFolderAsync(L"VpnPhonebookTest",
                                               storage::CreationCollisionOption::GenerateUniqueName)
                            .get();
    const auto file = folder.CreateFileAsync(L"rasphone.pbk").get();
    const std::wstring original = L"[Tailgate]\r\nType=2\r\nDevice=\r\nDEVICE=modem\r\n";
    storage::FileIO::WriteTextAsync(file, original).get();

    VpnPhonebook::RepairAsync(folder).get();
    const auto actual = storage::FileIO::ReadTextAsync(file).get();
    folder.DeleteAsync().get();

    EXPECT_EQ(actual, L"[Tailgate]\r\nType=2\r\nDevice=\r\nDEVICE=vpn\r\n");
}

TEST(Given_VpnPhonebook, When_ModemProfileHasBothDeviceFields_Then_OnlyUppercaseFieldChanges)
{
    std::string bytes = "[Other]\r\nType=2\r\nDEVICE=modem\r\n[Tailgate]\r\nType=2\r\n"
                        "Device=\r\nDEVICE=modem\r\nThirdPartyProfileInfo=opaque\r\n"
                        "[Another]\r\nDEVICE=modem\r\n";

    const bool changed = VpnPhonebook::SetVpnDeviceType(bytes);

    EXPECT_TRUE(changed);
    EXPECT_EQ(bytes,
              "[Other]\r\nType=2\r\nDEVICE=modem\r\n[Tailgate]\r\nType=2\r\n"
              "Device=\r\nDEVICE=vpn\r\nThirdPartyProfileInfo=opaque\r\n"
              "[Another]\r\nDEVICE=modem\r\n");
}

TEST(Given_VpnPhonebook, When_DeviceIsLastLineWithoutNewline_Then_RepairsIt)
{
    std::string bytes = "[Tailgate]\nType=2\nDEVICE=modem";

    const bool changed = VpnPhonebook::SetVpnDeviceType(bytes);

    EXPECT_TRUE(changed);
    EXPECT_EQ(bytes, "[Tailgate]\nType=2\nDEVICE=vpn");
}

TEST(Given_VpnPhonebook, When_DeviceAlreadyVpn_Then_DoesNotRewrite)
{
    const std::string original = "[Tailgate]\r\nType=2\r\nDEVICE=vpn\r\n";
    auto bytes = original;

    const bool changed = VpnPhonebook::SetVpnDeviceType(bytes);

    EXPECT_FALSE(changed);
    EXPECT_EQ(bytes, original);
}

TEST(Given_VpnPhonebook, When_PhonebookHasUtf8Bom_Then_PreservesEncoding)
{
    std::string bytes = "\xef\xbb\xbf[Tailgate]\r\nType=2\r\nDEVICE=modem\r\n";

    const bool changed = VpnPhonebook::SetVpnDeviceType(bytes);

    EXPECT_TRUE(changed);
    EXPECT_EQ(bytes, "\xef\xbb\xbf[Tailgate]\r\nType=2\r\nDEVICE=vpn\r\n");
}

class Given_VpnPhonebook : public testing::TestWithParam<std::string>
{
};

TEST_P(Given_VpnPhonebook, When_ProfileIsUnrecognizedOrAmbiguous_Then_PreservesEveryByte)
{
    const auto original = GetParam();
    auto bytes = original;

    const bool changed = VpnPhonebook::SetVpnDeviceType(bytes);

    EXPECT_FALSE(changed);
    EXPECT_EQ(bytes, original);
}

INSTANTIATE_TEST_SUITE_P(PhonebookFormats,
                         Given_VpnPhonebook,
                         testing::Values("",
                                         "[Other]\nType=2\nDEVICE=modem\n",
                                         "[Tailgate]\nType=1\nDEVICE=modem\n",
                                         "[Tailgate]\nDEVICE=modem\n",
                                         "[Tailgate]\nType=2\nDevice=modem\n",
                                         "[Tailgate]\nType=2\nDEVICE=unknown\n",
                                         "[Tailgate]\nType=2\nDEVICE=modem-extra\n",
                                         "[Tailgate]\nType=2\nDEVICE=modem\nDEVICE=vpn\n",
                                         "[Tailgate]\nType=2\nType=2\nDEVICE=modem\n",
                                         "[Tailgate]\nType=2\nDEVICE=modem\n[Tailgate]\n",
                                         std::string("[Tailgate]\nType=2\nDEVICE=modem\n") + '\0'));

} // namespace
