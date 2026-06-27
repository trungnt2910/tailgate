#include "tailgate/Logging.h"

#include <mutex>
#include <utility>

namespace tailgate
{
namespace
{

std::mutex SinkMutex;
LogSink Sink;

} // namespace

void SetLogSink(LogSink sink)
{
    std::lock_guard<std::mutex> lock(SinkMutex);
    Sink = std::move(sink);
}

void Log(LogLevel level, const std::string& component, const std::string& message)
{
    LogSink sink;
    {
        std::lock_guard<std::mutex> lock(SinkMutex);
        sink = Sink;
    }
    if (sink)
    {
        sink(level, component, message);
    }
}

const char* LogLevelName(LogLevel level)
{
    switch (level)
    {
    case LogLevel::Trace:
        return "trace";
    case LogLevel::Debug:
        return "debug";
    case LogLevel::Info:
        return "info";
    case LogLevel::Warning:
        return "warning";
    case LogLevel::Error:
        return "error";
    }
    return "unknown";
}

} // namespace tailgate
