#pragma once

#include <functional>
#include <string>

namespace tailgate
{

enum class LogLevel
{
    Trace,
    Debug,
    Info,
    Warning,
    Error,
};

using LogSink = std::function<void(LogLevel, const std::string&, const std::string&)>;

void SetLogSink(LogSink sink);
void Log(LogLevel level, const std::string& component, const std::string& message);
[[nodiscard]] const char* LogLevelName(LogLevel level);

} // namespace tailgate
