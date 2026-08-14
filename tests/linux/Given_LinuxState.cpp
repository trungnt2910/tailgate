#include <filesystem>
#include <fstream>
#include <string>

#include <unistd.h>

#include <gtest/gtest.h>

#include "LinuxState.h"

#include "LinuxTestEnvironment.h"

TEST(Given_IdentityWithDiscoKey, When_Persisting_Then_AllClientKeysRoundTrip)
{
    tailgate::test::LinuxTestHome home("linux-state");
    tailgate::linux_frontend::IdentityState identity;
    identity.MachinePrivateKey.fill(1);
    identity.NodePrivateKey.fill(2);
    identity.DiscoPrivateKey.fill(3);
    identity.Hostname = "host";
    identity.RegistrationComplete = true;
    const std::filesystem::path state = home.Path() / ".tailgate";

    tailgate::linux_frontend::WriteIdentity(identity);
    std::ofstream(state / "hosted-profiles.json") << R"({"MachinePrivateKey":"secret"})";
    const auto restored = tailgate::linux_frontend::ReadIdentity();
    tailgate::linux_frontend::RemoveLegacyHostedProfiles();

    EXPECT_TRUE(restored.has_value());
    EXPECT_EQ(restored->MachinePrivateKey, identity.MachinePrivateKey);
    EXPECT_EQ(restored->NodePrivateKey, identity.NodePrivateKey);
    EXPECT_EQ(restored->DiscoPrivateKey, identity.DiscoPrivateKey);
    EXPECT_EQ(restored->Hostname, identity.Hostname);
    EXPECT_TRUE(restored->RegistrationComplete);
    EXPECT_FALSE(std::filesystem::exists(state / "hosted-profiles.json"));
}

TEST(Given_PersistedProfile, When_RemovingProfile_Then_IdentityBoundStateIsDeleted)
{
    tailgate::test::LinuxTestHome home("linux-logout");
    tailgate::linux_frontend::IdentityState identity;
    identity.MachinePrivateKey.fill(1);
    identity.NodePrivateKey.fill(2);
    identity.DiscoPrivateKey.fill(3);
    identity.Hostname = "host";
    tailgate::linux_frontend::SettingsState settings;
    settings.Hostname = "host";
    tailgate::linux_frontend::AcmeState acme;
    acme.Domain = "host.example.ts.net";
    tailgate::linux_frontend::RelaySessionState relay;
    relay.ServerUrl = "https://relay.example.ts.net:10000";
    const std::filesystem::path state = home.Path() / ".tailgate";
    tailgate::linux_frontend::WriteIdentity(identity);
    tailgate::linux_frontend::WriteSettings(settings);
    tailgate::linux_frontend::WriteAcmeState(acme);
    tailgate::linux_frontend::WriteRelaySession(relay);

    tailgate::linux_frontend::RemoveProfileState();
    const bool identityExists = std::filesystem::exists(state / "identity.json");
    const bool settingsExist = std::filesystem::exists(state / "settings.json");
    const bool acmeExists = std::filesystem::exists(state / "acme.json");
    const bool relaySessionExists = std::filesystem::exists(state / "relay-session.json");

    EXPECT_FALSE(identityExists);
    EXPECT_FALSE(settingsExist);
    EXPECT_FALSE(acmeExists);
    EXPECT_FALSE(relaySessionExists);
}

TEST(Given_PendingLogin, When_PersistingDaemonStatus_Then_AuthorizationUrlRoundTrips)
{
    tailgate::test::LinuxTestHome home("linux-auth-status");
    tailgate::linux_frontend::DaemonStatus status;
    status.ProcessId = getpid();
    status.BackendState = "NeedsLogin";
    status.AuthorizationUrl = "https://login.tailscale.com/a/fake-login-code";

    tailgate::linux_frontend::WriteDaemonStatus(status);
    const auto restored = tailgate::linux_frontend::ReadDaemonStatus();

    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(restored->BackendState, "NeedsLogin");
    EXPECT_EQ(restored->AuthorizationUrl, status.AuthorizationUrl);
}
