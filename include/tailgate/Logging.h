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
// Messages below the minimum level are discarded before reaching the sink. Defaults to Trace;
// release frontends can raise it to keep hot-path trace logging out of production logs.
void SetMinimumLogLevel(LogLevel level);
void Log(LogLevel level, const std::string& component, const std::string& message);
[[nodiscard]] const char* LogLevelName(LogLevel level);

} // namespace tailgate
