#pragma once

#include <format>
#include <string>
#include <utility>

#include <tailgate/base/Logging.h>

namespace tailgate::base
{

class Logger final
{
public:
    explicit Logger(std::string component) : m_component(std::move(component))
    {
    }

    template <typename... Args>
    void Log(LogLevel level, std::format_string<Args...> format, Args&&... args) const
    {
        tailgate::base::Log(level, m_component, std::format(format, std::forward<Args>(args)...));
    }

    template <typename... Args>
    void LogTrace(std::format_string<Args...> format, Args&&... args) const
    {
        Log(LogLevel::Trace, format, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void LogDebug(std::format_string<Args...> format, Args&&... args) const
    {
        Log(LogLevel::Debug, format, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void LogInfo(std::format_string<Args...> format, Args&&... args) const
    {
        Log(LogLevel::Info, format, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void LogWarning(std::format_string<Args...> format, Args&&... args) const
    {
        Log(LogLevel::Warning, format, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void LogError(std::format_string<Args...> format, Args&&... args) const
    {
        Log(LogLevel::Error, format, std::forward<Args>(args)...);
    }

private:
    std::string m_component;
};

} // namespace tailgate::base
