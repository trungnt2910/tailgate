#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tailgate::linux_frontend
{

// Returns the first CA bundle path that exists among the well-known locations used by common
// Linux distributions, so the frontend does not hard-code a single distro's layout.
[[nodiscard]] std::string SystemCaBundlePath();

// Reads the detected system CA bundle as PEM bytes.
[[nodiscard]] std::vector<std::uint8_t> SystemCaBundle();

} // namespace tailgate::linux_frontend
