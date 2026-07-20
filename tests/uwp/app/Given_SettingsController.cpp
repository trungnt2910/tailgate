#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

#include <winrt/Windows.Storage.h>

#include <gtest/gtest.h>

#include "app/controller/impl/SettingsControllerImpl.h"

#include "TestHost.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace storage = winrt::Windows::Storage;

class Given_SettingsController : public testing::Test
{
protected:
    void SetUp() override
    {
        TestHost::RunOnUiThread(
            [this]
            {
                m_subject = std::make_unique<SettingsControllerImpl>();
                m_subject->Clear();
            });
    }

    void TearDown() override
    {
        TestHost::RunOnUiThread(
            [this]
            {
                m_subject->Clear();
                m_subject.reset();
            });
    }

    [[nodiscard]] static std::filesystem::path StatePath()
    {
        const auto folder = storage::ApplicationData::Current().LocalFolder().Path();
        return std::filesystem::path(folder.c_str()) / L"tailgate-state.json";
    }

    std::unique_ptr<SettingsControllerImpl> m_subject;
};

TEST_F(Given_SettingsController, When_ConnectionValuesAreSet_Then_StateAndSnapshotAreUpdated)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->SetAuthentication(L"https://example.com", L"test-auth-key");
            m_subject->SetHostname(L"test-device");
            m_subject->SetExitNode(L"exit.example.ts.net", false);
        });

    const auto& state = m_subject->GetState();
    EXPECT_EQ(state.TailgateServer(), L"https://example.com");
    EXPECT_EQ(state.AuthKey(), L"test-auth-key");
    EXPECT_EQ(state.Hostname(), L"test-device");
    EXPECT_EQ(state.ExitNode(), L"exit.example.ts.net");
    EXPECT_EQ(state.ExitNodeSelection(), L"exit.example.ts.net");
    EXPECT_EQ(state.ConnectionSettings().TailgateServer, L"https://example.com");
    EXPECT_EQ(state.ConnectionSettings().Hostname, L"test-device");
    EXPECT_EQ(state.ConnectionSettings().ExitNode, L"exit.example.ts.net");
}

TEST_F(Given_SettingsController, When_ExitNodeIsClearedPreservingSelection_Then_SelectionRemains)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->SetExitNode(L"exit.example.ts.net", false);
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->SetExitNode(L"", true);
        });

    EXPECT_TRUE(m_subject->GetState().ExitNode().empty());
    EXPECT_EQ(m_subject->GetState().ExitNodeSelection(), L"exit.example.ts.net");
}

TEST_F(Given_SettingsController, When_ConnectionSnapshotIsRestored_Then_MissingValuesAreRemoved)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->SetAuthentication(L"https://old.example.com", L"");
            m_subject->SetHostname(L"old-host");
            m_subject->SetExitNode(L"old-exit.example.ts.net", false);
        });
    ConnectionSettingsSnapshot snapshot;
    snapshot.TailgateServer = L"https://new.example.com";
    snapshot.ExitNodeSelection = L"remembered-exit.example.ts.net";

    TestHost::RunOnUiThread(
        [this, &snapshot]
        {
            m_subject->RestoreConnectionSettings(snapshot);
        });

    const auto& state = m_subject->GetState();
    EXPECT_EQ(state.TailgateServer(), L"https://new.example.com");
    EXPECT_TRUE(state.Hostname().empty());
    EXPECT_TRUE(state.ExitNode().empty());
    EXPECT_EQ(state.ExitNodeSelection(), L"remembered-exit.example.ts.net");
    EXPECT_EQ(state.ConnectionSettings(), snapshot);
}

TEST_F(Given_SettingsController, When_ProfilePictureCacheIsCleared_Then_UrlIsRemoved)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->SetCachedProfilePictureUrl(L"https://example.com/profile.png");
        });
    ASSERT_FALSE(m_subject->GetState().CachedProfilePictureUrl().empty());

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->ClearCachedProfilePictureUrl();
        });

    EXPECT_TRUE(m_subject->GetState().CachedProfilePictureUrl().empty());
}

TEST_F(Given_SettingsController, When_StateFileIsValid_Then_AccountAndDeviceDataAreLoaded)
{
    const std::string stateJson = R"json({
        "TailnetName": "example.ts.net",
        "AccountName": "user@example.com",
        "SelfAddress": "100.64.0.1",
        "Devices": [
            {
                "Name": "local.example.ts.net",
                "Address": "100.64.0.1",
                "IPv6": "fd7a:115c:a1e0::1",
                "OS": "Windows",
                "Online": true
            },
            42
        ],
        "DeviceGroups": [
            {
                "Name": "Example Group",
                "Devices": [
                    {
                        "Name": "peer.example.ts.net",
                        "Address": "100.64.0.2",
                        "ExitNodeOption": true
                    },
                    {}
                ]
            }
        ]
    })json";
    std::ofstream stream(StatePath(), std::ios::trunc);
    stream << stateJson;
    stream.close();

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Reload();
        });

    const auto& state = m_subject->GetState();
    ASSERT_EQ(state.Devices().size(), 2U);
    EXPECT_TRUE(state.Loaded());
    EXPECT_EQ(state.TailnetName(), L"example.ts.net");
    EXPECT_EQ(state.TailnetDisplayName(), L"example.ts.net");
    EXPECT_EQ(state.AccountName(), L"user@example.com");
    EXPECT_EQ(state.SelfAddress(), L"100.64.0.1");
    EXPECT_EQ(state.Devices()[0].Name, L"local.example.ts.net");
    EXPECT_TRUE(state.Devices()[0].Online);
    EXPECT_EQ(state.Devices()[1].Group, L"Example Group");
    EXPECT_TRUE(state.Devices()[1].ExitNodeOption);
}

TEST_F(Given_SettingsController, When_StateFileIsInvalid_Then_ItIsIgnored)
{
    std::ofstream stream(StatePath(), std::ios::trunc);
    stream << "not-json";
    stream.close();

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Reload();
        });

    EXPECT_FALSE(m_subject->GetState().Loaded());
    EXPECT_TRUE(m_subject->GetState().Devices().empty());
    EXPECT_TRUE(m_subject->GetState().TailnetName().empty());
}

TEST_F(Given_SettingsController, When_Cleared_Then_PersistedConnectionAndStateFileAreRemoved)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->SetAuthentication(L"https://example.com", L"test-auth-key");
            m_subject->SetHostname(L"test-device");
        });
    std::ofstream stream(StatePath(), std::ios::trunc);
    stream << R"json({"TailnetName":"example.ts.net"})json";
    stream.close();
    ASSERT_TRUE(std::filesystem::exists(StatePath()));

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Clear();
        });

    EXPECT_TRUE(m_subject->GetState().TailgateServer().empty());
    EXPECT_TRUE(m_subject->GetState().AuthKey().empty());
    EXPECT_TRUE(m_subject->GetState().Hostname().empty());
    EXPECT_FALSE(m_subject->GetState().Loaded());
    EXPECT_FALSE(std::filesystem::exists(StatePath()));
}

} // namespace
} // namespace tailgate::uwp::tests
