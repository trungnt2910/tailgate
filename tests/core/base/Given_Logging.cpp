#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/base/Logger.h>

namespace tailgate::test
{
namespace
{

struct LogEntry
{
    tailgate::base::LogLevel Level = tailgate::base::LogLevel::Trace;
    std::string Component;
    std::string Message;
};

class Given_Logging : public ::testing::Test
{
protected:
    void SetUp() override
    {
        tailgate::base::SetMinimumLogLevel(tailgate::base::LogLevel::Trace);
        tailgate::base::SetLogSink(
            [this](tailgate::base::LogLevel level,
                   const std::string& component,
                   const std::string& message)
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
        tailgate::base::SetLogSink({});
        tailgate::base::SetMinimumLogLevel(tailgate::base::LogLevel::Trace);
    }

    std::vector<LogEntry> m_entries;
};

TEST_F(Given_Logging, When_LoggerLogsFormattedMessage_Then_SinkReceivesComponentAndMessage)
{
    tailgate::base::Logger logger("test-component");

    logger.Log(tailgate::base::LogLevel::Info, "peer {} uses port {}", "example", 41641);

    ASSERT_EQ(m_entries.size(), 1U);
    EXPECT_EQ(m_entries[0].Level, tailgate::base::LogLevel::Info);
    EXPECT_EQ(m_entries[0].Component, "test-component");
    EXPECT_EQ(m_entries[0].Message, "peer example uses port 41641");
}

TEST_F(Given_Logging, When_SeverityHelpersLog_Then_SinkReceivesMatchingLevels)
{
    tailgate::base::Logger logger("test-component");

    logger.LogTrace("trace");
    logger.LogDebug("debug");
    logger.LogInfo("info");
    logger.LogWarning("warning");
    logger.LogError("error");

    ASSERT_EQ(m_entries.size(), 5U);
    EXPECT_EQ(m_entries[0].Level, tailgate::base::LogLevel::Trace);
    EXPECT_EQ(m_entries[1].Level, tailgate::base::LogLevel::Debug);
    EXPECT_EQ(m_entries[2].Level, tailgate::base::LogLevel::Info);
    EXPECT_EQ(m_entries[3].Level, tailgate::base::LogLevel::Warning);
    EXPECT_EQ(m_entries[4].Level, tailgate::base::LogLevel::Error);
}

TEST_F(Given_Logging, When_MessageIsBelowMinimumLevel_Then_SinkDoesNotReceiveIt)
{
    tailgate::base::Logger logger("test-component");
    tailgate::base::SetMinimumLogLevel(tailgate::base::LogLevel::Warning);

    logger.LogDebug("discarded {}", "message");

    EXPECT_TRUE(m_entries.empty());
}

} // namespace
} // namespace tailgate::test
