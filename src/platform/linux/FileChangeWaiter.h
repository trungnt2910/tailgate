#pragma once

#include <chrono>
#include <string>

#include "UniqueFd.h"

namespace tailgate::linux_frontend
{

class FileChangeWaiter final
{
public:
    explicit FileChangeWaiter(const std::string& directory);

    [[nodiscard]] int Descriptor() const noexcept;
    [[nodiscard]] bool TakeChange(const std::string& name);
    [[nodiscard]] bool WaitForChange(const std::string& name,
                                     std::chrono::milliseconds timeout,
                                     bool interruptible = false);

private:
    UniqueFd m_descriptor;
};

} // namespace tailgate::linux_frontend
