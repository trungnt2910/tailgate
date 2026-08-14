#include <gtest/gtest.h>

#include <tailgate/cli/Arguments.h>

TEST(Given_Arguments, When_ParsingUp_Then_TailscaleStyleOptionsAreTyped)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"up",
                                                            "--auth-key=file:key.txt",
                                                            "--hostname",
                                                            "workstation",
                                                            "--accept-dns=false",
                                                            "--exit-node",
                                                            "exit-node",
                                                            "--tailgate",
                                                            "https://relay.example.ts.net:10000"});

    EXPECT_TRUE(arguments.SelectedCommand == tailgate::cli::Command::Up);
    EXPECT_TRUE(arguments.Up.AuthKey == "file:key.txt");
    EXPECT_TRUE(arguments.Up.Hostname == "workstation");
    EXPECT_TRUE(!arguments.Up.AcceptDns);
    EXPECT_EQ(arguments.Up.ExitNode, "exit-node");
    EXPECT_EQ(arguments.Up.TailgateUrl, "https://relay.example.ts.net:10000");
    EXPECT_TRUE(arguments.Up.HostnameSet);
    EXPECT_TRUE(arguments.Up.AcceptDnsSet);
    EXPECT_TRUE(arguments.Up.ExitNodeSet);
    EXPECT_TRUE(arguments.Up.TailgateUrlSet);
    EXPECT_FALSE(arguments.Up.Reset);
}

TEST(Given_UpResetWithoutPreferences, When_Parsing_Then_DefaultsAreExplicitlyRequested)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"up", "--reset"});

    EXPECT_EQ(arguments.SelectedCommand, tailgate::cli::Command::Up);
    EXPECT_TRUE(arguments.Up.Reset);
    EXPECT_FALSE(arguments.Up.HostnameSet);
    EXPECT_FALSE(arguments.Up.AcceptDnsSet);
    EXPECT_FALSE(arguments.Up.ExitNodeSet);
    EXPECT_FALSE(arguments.Up.TailgateUrlSet);
}

TEST(Given_BareAcceptDnsFlag, When_ParsingUp_Then_DnsIsExplicitlyAccepted)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"up", "--accept-dns"});

    EXPECT_TRUE(arguments.Up.AcceptDns);
    EXPECT_TRUE(arguments.Up.AcceptDnsSet);
}

TEST(Given_SeparatedAcceptDnsValue, When_ParsingUp_Then_ParsingFails)
{
    const auto parse = []()
    {
        (void)tailgate::cli::Arguments::Parse({"up", "--accept-dns", "false"});
    };

    EXPECT_THROW(parse(), tailgate::cli::ArgumentError);
}

TEST(Given_QrOptions, When_ParsingUp_Then_PresentationIsTyped)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"up", "--qr", "--qr-format=small"});

    EXPECT_TRUE(arguments.Up.Qr);
    EXPECT_EQ(arguments.Up.QrFormat, "small");
}

TEST(Given_UnsupportedQrFormat, When_ParsingUp_Then_ParsingFails)
{
    const auto parse = []()
    {
        (void)tailgate::cli::Arguments::Parse({"up", "--qr-format=punch-card"});
    };

    EXPECT_THROW(parse(), tailgate::cli::ArgumentError);
}

TEST(Given_Arguments, When_ParsingSet_Then_OnlySpecifiedPreferencesArePresent)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"set", "--exit-node", "exit-node"});

    EXPECT_EQ(arguments.SelectedCommand, tailgate::cli::Command::Set);
    EXPECT_FALSE(arguments.Set.Hostname.has_value());
    EXPECT_EQ(arguments.Set.ExitNode, "exit-node");
}

TEST(Given_Arguments, When_ParsingMultipleSetOptions_Then_ChangesAreAtomic)
{
    const auto arguments = tailgate::cli::Arguments::Parse(
        {"set", "--hostname", "workstation", "--exit-node", "exit-node"});

    EXPECT_EQ(arguments.SelectedCommand, tailgate::cli::Command::Set);
    EXPECT_EQ(arguments.Set.Hostname, "workstation");
    EXPECT_EQ(arguments.Set.ExitNode, "exit-node");
}

TEST(Given_EmptyTailgateUrl, When_ParsingSet_Then_HostedModeIsExplicitlyDisabled)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"set", "--tailgate="});

    EXPECT_EQ(arguments.SelectedCommand, tailgate::cli::Command::Set);
    EXPECT_TRUE(arguments.Set.TailgateUrl.has_value());
    EXPECT_TRUE(arguments.Set.TailgateUrl->empty());
}

TEST(Given_Arguments, When_ParsingStatusJson_Then_StatusOptionsAreTyped)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"status", "--json"});

    EXPECT_TRUE(arguments.SelectedCommand == tailgate::cli::Command::Status);
    EXPECT_TRUE(arguments.Status.Json);
}

TEST(Given_Arguments, When_OptionIsUnknown_Then_ParsingFails)
{
    const auto parse = []()
    {
        (void)tailgate::cli::Arguments::Parse({"up", "--definitely-unknown"});
    };

    EXPECT_THROW(parse(), tailgate::cli::ArgumentError);
}

TEST(Given_Arguments, When_ParsingLogout_Then_LogoutIsSelected)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"logout"});

    EXPECT_EQ(arguments.SelectedCommand, tailgate::cli::Command::Logout);
}

TEST(Given_LogoutWithUnsupportedReason, When_Parsing_Then_ParsingFails)
{
    const auto parse = []()
    {
        (void)tailgate::cli::Arguments::Parse({"logout", "--reason=test"});
    };

    EXPECT_THROW(parse(), tailgate::cli::ArgumentError);
}

TEST(Given_Arguments, When_EphemeralFlagIsUsed_Then_ParsingFails)
{
    const auto parse = []()
    {
        (void)tailgate::cli::Arguments::Parse({"up", "--ephemeral=false"});
    };

    EXPECT_THROW(parse(), tailgate::cli::ArgumentError);
}

TEST(Given_Arguments, When_ParsingPing_Then_TailscaleStyleOptionsAreTyped)
{
    const auto arguments = tailgate::cli::Arguments::Parse(
        {"ping", "peer", "-c", "4", "--timeout", "2", "--until-direct=false"});

    EXPECT_TRUE(arguments.SelectedCommand == tailgate::cli::Command::Ping);
    EXPECT_TRUE(arguments.Ping.Target == "peer");
    EXPECT_TRUE(arguments.Ping.Count == 4);
    EXPECT_TRUE(arguments.Ping.TimeoutSeconds == 2);
    EXPECT_TRUE(!arguments.Ping.UntilDirect);
}

TEST(Given_Arguments, When_ParsingPingWithBareUntilDirect_Then_ItIsEnabled)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"ping", "peer", "--until-direct"});

    EXPECT_TRUE(arguments.SelectedCommand == tailgate::cli::Command::Ping);
    EXPECT_TRUE(arguments.Ping.UntilDirect);
}

TEST(Given_PingWithoutProtocolFlag, When_Parsing_Then_DiscoIsTheDefault)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"ping", "peer"});

    EXPECT_FALSE(arguments.Ping.Tsmp);
}

TEST(Given_PingWithTsmpFlag, When_Parsing_Then_TsmpIsSelected)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"ping", "peer", "--tsmp"});

    EXPECT_TRUE(arguments.Ping.Tsmp);
}

TEST(Given_PingHelp, When_FormattingTsmpFlag_Then_OfficialDescriptionIsUsed)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"ping", "--help"});

    const bool hasOfficialDescription =
        arguments.HelpOutput.find(
            "do a TSMP-level ping (through WireGuard, but not either host OS stack)") !=
        std::string::npos;

    EXPECT_TRUE(hasOfficialDescription);
}

TEST(Given_Arguments, When_ParsingFunnel_Then_PortsAndForegroundModeAreTyped)
{
    const auto arguments = tailgate::cli::Arguments::Parse(
        {"funnel", "--tls-terminated-tcp=10000", "tcp://localhost:9000"});

    EXPECT_EQ(arguments.SelectedCommand, tailgate::cli::Command::Funnel);
    EXPECT_EQ(arguments.Funnel.Port, 10000);
    EXPECT_EQ(arguments.Funnel.LocalPort, 9000);
    EXPECT_FALSE(arguments.Funnel.Off);
    EXPECT_FALSE(arguments.Funnel.Background);
}

TEST(Given_Arguments, When_ParsingBackgroundFunnelOff_Then_DisableIsTyped)
{
    const auto arguments =
        tailgate::cli::Arguments::Parse({"funnel", "--tls-terminated-tcp=443", "--bg", "off"});

    EXPECT_EQ(arguments.SelectedCommand, tailgate::cli::Command::Funnel);
    EXPECT_EQ(arguments.Funnel.Port, 443);
    EXPECT_TRUE(arguments.Funnel.Off);
    EXPECT_TRUE(arguments.Funnel.Background);
}

TEST(Given_Arguments, When_ParsingExpose_Then_PortAndBackgroundModeAreTyped)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"expose", "--port=10000", "--bg"});

    EXPECT_EQ(arguments.SelectedCommand, tailgate::cli::Command::Expose);
    EXPECT_EQ(arguments.Expose.Port, 10000);
    EXPECT_TRUE(arguments.Expose.Background);
    EXPECT_FALSE(arguments.Expose.Off);
}

TEST(Given_Arguments, When_ParsingExposeOff_Then_DisableIsTyped)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"expose", "--port=443", "off"});

    EXPECT_EQ(arguments.SelectedCommand, tailgate::cli::Command::Expose);
    EXPECT_EQ(arguments.Expose.Port, 443);
    EXPECT_TRUE(arguments.Expose.Off);
}

TEST(Given_Arguments, When_TailgateUrlIsNotHttps_Then_ParsingFails)
{
    const auto parse = []()
    {
        (void)tailgate::cli::Arguments::Parse({"up", "--tailgate=http://relay.example.com"});
    };

    EXPECT_THROW(parse(), tailgate::cli::ArgumentError);
}

TEST(Given_ShortTailgateUrl, When_ParsingUp_Then_HttpsIsImplied)
{
    const auto arguments =
        tailgate::cli::Arguments::Parse({"up", "--tailgate=relay.example.ts.net:10000"});

    EXPECT_EQ(arguments.Up.TailgateUrl, "https://relay.example.ts.net:10000");
}

TEST(Given_TopLevelHelp, When_Formatting_Then_RegisteredCommandsUseOfficialLayout)
{
    const std::string help = tailgate::cli::Arguments::HelpText();

    const bool hasDescription =
        help.starts_with("The easiest, most secure way to use WireGuard.\n\nUSAGE\n");
    const bool hasUsage =
        help.find("tailgate [flags] <subcommand> [command flags]") != std::string::npos;
    const bool hasRegisteredCommand =
        help.find("\n  up ") != std::string::npos &&
        help.find("Connect to Tailscale, logging in if needed") != std::string::npos;

    EXPECT_TRUE(hasDescription);
    EXPECT_TRUE(hasUsage);
    EXPECT_TRUE(hasRegisteredCommand);
}

TEST(Given_SubcommandHelp, When_Parsing_Then_OnlySubcommandHelpIsReturned)
{
    const auto arguments = tailgate::cli::Arguments::Parse({"up", "--help"});

    const bool hasUpUsage =
        arguments.HelpOutput.find("USAGE\n  tailgate up [flags]") != std::string::npos;
    const bool hasUpFlag = arguments.HelpOutput.find("--accept-dns") != std::string::npos;
    const bool hasTopLevelCommands = arguments.HelpOutput.find("SUBCOMMANDS") != std::string::npos;

    EXPECT_EQ(arguments.SelectedCommand, tailgate::cli::Command::Help);
    EXPECT_TRUE(hasUpUsage);
    EXPECT_TRUE(hasUpFlag);
    EXPECT_FALSE(hasTopLevelCommands);
}
