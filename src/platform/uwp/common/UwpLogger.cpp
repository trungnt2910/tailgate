#include "UwpLogger.h"

#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <winrt/Windows.Storage.h>

#include <tailgate/base/Logging.h>

namespace tailgate::uwp
{

namespace storage = winrt::Windows::Storage;

void InstallUwpLogSink(const winrt::hstring& fileName)
{
    // std::osyncstream is buggy on Windows UWP.
    auto stream = std::make_shared<std::ofstream>();
    auto streamMutex = std::make_shared<std::mutex>();
    try
    {
        const auto folder = storage::ApplicationData::Current().TemporaryFolder().Path();
        const std::filesystem::path path = std::filesystem::path(folder.c_str()) / fileName.c_str();
        stream->open(path, std::ios::app);
    }
    catch (...)
    {
        stream->close();
    }
    tailgate::base::SetLogSink(
        [stream, streamMutex](tailgate::base::LogLevel level,
                              const std::string& component,
                              const std::string& message)
        {
            std::lock_guard lock(*streamMutex);
            if (!stream->is_open())
            {
                return;
            }
            const auto timestamp =
                std::chrono::floor<std::chrono::milliseconds>(std::chrono::system_clock::now());
            *stream << std::format("{:%Y-%m-%dT%H:%M:%SZ} [pid={} tid={}] [{}] {}: {}\n",
                                   timestamp,
                                   GetCurrentProcessId(),
                                   GetCurrentThreadId(),
                                   tailgate::base::LogLevelName(level),
                                   component,
                                   message)
                    << std::flush;
        });
}

} // namespace tailgate::uwp
