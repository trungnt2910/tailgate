#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/Logger.h>

namespace tailgate::test
{
namespace
{

struct LogEntry
{
    LogLevel Level = LogLevel::Trace;
    std::string Component;
    std::string Message;
};

class Given_Logging : public ::testing::Test
{
protected:
    void SetUp() override
    {
        SetMinimumLogLevel(LogLevel::Trace);
        SetLogSink(
            [this](LogLevel level, const std::string& component, const std::string& message)
            {
                m_entries.push_back(LogEntry{
                    .Level = level,
                    .Component = component,
                    .Message = message,
                });
            });
    }

    void TearDown() override
    {
        SetLogSink({});
        SetMinimumLogLevel(LogLevel::Trace);
    }

    std::vector<LogEntry> m_entries;
};

TEST_F(Given_Logging, When_LoggerLogsFormattedMessage_Then_SinkReceivesComponentAndMessage)
{
    Logger logger("test-component");

    logger.Log(LogLevel::Info, "peer {} uses port {}", "example", 41641);

    ASSERT_EQ(m_entries.size(), 1U);
    EXPECT_EQ(m_entries[0].Level, LogLevel::Info);
    EXPECT_EQ(m_entries[0].Component, "test-component");
    EXPECT_EQ(m_entries[0].Message, "peer example uses port 41641");
}

TEST_F(Given_Logging, When_SeverityHelpersLog_Then_SinkReceivesMatchingLevels)
{
    Logger logger("test-component");

    logger.LogTrace("trace");
    logger.LogDebug("debug");
    logger.LogInfo("info");
    logger.LogWarning("warning");
    logger.LogError("error");

    ASSERT_EQ(m_entries.size(), 5U);
    EXPECT_EQ(m_entries[0].Level, LogLevel::Trace);
    EXPECT_EQ(m_entries[1].Level, LogLevel::Debug);
    EXPECT_EQ(m_entries[2].Level, LogLevel::Info);
    EXPECT_EQ(m_entries[3].Level, LogLevel::Warning);
    EXPECT_EQ(m_entries[4].Level, LogLevel::Error);
}

TEST_F(Given_Logging, When_MessageIsBelowMinimumLevel_Then_SinkDoesNotReceiveIt)
{
    Logger logger("test-component");
    SetMinimumLogLevel(LogLevel::Warning);

    logger.LogDebug("discarded {}", "message");

    EXPECT_TRUE(m_entries.empty());
}

} // namespace
} // namespace tailgate::test
