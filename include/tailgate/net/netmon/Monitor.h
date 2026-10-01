#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tailgate::net::netmon
{

struct Network
{
    // Absent means OS routing. Explicit adapter selection is a platform bypass mechanism.
    std::optional<std::string> Interface;
    std::vector<std::string> Addresses;
    [[nodiscard]] bool operator==(const Network&) const = default;
};

struct Snapshot
{
    std::uint64_t Generation = 0;
    std::vector<Network> Networks;
};

class Monitor
{
public:
    virtual ~Monitor() = default;
    // Changes wake the injected event loop. Enumeration is performed on its owner.
    [[nodiscard]] virtual Snapshot Current() = 0;
};

} // namespace tailgate::net::netmon
