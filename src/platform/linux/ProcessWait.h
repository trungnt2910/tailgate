#pragma once

#include <chrono>

#include <sys/types.h>

namespace tailgate::linux_frontend
{

[[nodiscard]] bool WaitForProcessExit(pid_t processId, std::chrono::milliseconds timeout);

} // namespace tailgate::linux_frontend
