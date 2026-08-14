#pragma once

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <optional>
#include <string>
#include <system_error>

#include <unistd.h>

namespace tailgate::test
{

class LinuxTestHome final
{
public:
    explicit LinuxTestHome(const std::string& name)
    {
        static std::atomic<std::uint64_t> sequence = 0;
        const std::uint64_t identifier = ++sequence;
        const auto timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
        m_path = std::filesystem::temp_directory_path() /
                 std::format("tailgate-test-{}-{}-{}-{}", name, getpid(), timestamp, identifier);
        std::filesystem::create_directories(m_path);
        if (const char* previous = std::getenv("HOME"))
        {
            m_previousHome = previous;
        }
        if (setenv("HOME", m_path.c_str(), 1) != 0)
        {
            const int error = errno;
            std::error_code cleanupError;
            std::filesystem::remove_all(m_path, cleanupError);
            throw std::system_error(error, std::generic_category());
        }
    }

    ~LinuxTestHome()
    {
        if (m_previousHome)
        {
            (void)setenv("HOME", m_previousHome->c_str(), 1);
        }
        else
        {
            (void)unsetenv("HOME");
        }
        std::error_code error;
        std::filesystem::remove_all(m_path, error);
    }

    LinuxTestHome(const LinuxTestHome&) = delete;
    LinuxTestHome& operator=(const LinuxTestHome&) = delete;

    [[nodiscard]] const std::filesystem::path& Path() const
    {
        return m_path;
    }

private:
    std::filesystem::path m_path;
    std::optional<std::string> m_previousHome;
};

} // namespace tailgate::test
