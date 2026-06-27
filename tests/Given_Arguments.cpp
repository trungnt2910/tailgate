#include <gtest/gtest.h>

#include "tailgate/cli/Arguments.h"

TEST(Tailgate, GivenArguments_WhenParsingUp_ThenTailscaleStyleOptionsAreTyped)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"up",
                                                            "--auth-key=file:key.txt",
                                                            "--hostname",
                                                            "workstation",
                                                            "--accept-dns=false",
                                                            "--exit-node",
                                                            "ishar"});

    ASSERT_TRUE(arguments.SelectedCommand == tailgate::cli::Command::Up);
    ASSERT_TRUE(arguments.Up.AuthKey == "file:key.txt");
    ASSERT_TRUE(arguments.Up.Hostname == "workstation");
    ASSERT_TRUE(!arguments.Up.AcceptDns);
    ASSERT_EQ(arguments.Up.ExitNode, "ishar");
}

TEST(Tailgate, GivenArguments_WhenParsingSet_ThenOnlySpecifiedPreferencesArePresent)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"set", "--exit-node", "ishar"});

    ASSERT_EQ(arguments.SelectedCommand, tailgate::cli::Command::Set);
    ASSERT_FALSE(arguments.Set.Hostname.has_value());
    ASSERT_EQ(arguments.Set.ExitNode, "ishar");
}

TEST(Tailgate, GivenArguments_WhenParsingMultipleSetOptions_ThenChangesAreAtomic)
{
    const auto arguments = tailgate::cli::Arguments::Parse(
        {"set", "--hostname", "workstation", "--exit-node", "ishar"});

    ASSERT_EQ(arguments.SelectedCommand, tailgate::cli::Command::Set);
    ASSERT_EQ(arguments.Set.Hostname, "workstation");
    ASSERT_EQ(arguments.Set.ExitNode, "ishar");
}

TEST(Tailgate, GivenArguments_WhenParsingStatusJson_ThenStatusOptionsAreTyped)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"status", "--json"});

    ASSERT_TRUE(arguments.SelectedCommand == tailgate::cli::Command::Status);
    ASSERT_TRUE(arguments.Status.Json);
}

TEST(Tailgate, GivenArguments_WhenOptionIsUnknown_ThenParsingFails)
{
    const auto parse = []()
    {
        (void)tailgate::cli::Arguments::Parse({"up", "--definitely-unknown"});
    };

    EXPECT_THROW(parse(), tailgate::cli::ArgumentError);
}

TEST(Tailgate, GivenArguments_WhenParsingPing_ThenTailscaleStyleOptionsAreTyped)
{
    const auto arguments = tailgate::cli::Arguments::Parse(
        {"ping", "ishar", "-c", "4", "--timeout", "2", "--until-direct=false"});

    ASSERT_TRUE(arguments.SelectedCommand == tailgate::cli::Command::Ping);
    ASSERT_TRUE(arguments.Ping.Target == "ishar");
    ASSERT_TRUE(arguments.Ping.Count == 4);
    ASSERT_TRUE(arguments.Ping.TimeoutSeconds == 2);
    ASSERT_TRUE(!arguments.Ping.UntilDirect);
}

TEST(Tailgate, GivenArguments_WhenParsingPingWithBareUntilDirect_ThenItIsEnabled)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"ping", "ishar", "--until-direct"});

    ASSERT_TRUE(arguments.SelectedCommand == tailgate::cli::Command::Ping);
    ASSERT_TRUE(arguments.Ping.UntilDirect);
}
