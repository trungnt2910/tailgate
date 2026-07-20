#pragma once

#include <cstdint>

namespace tailgate::uwp::bg::manager
{

struct TransportId
{
    std::uint32_t Value = 0;

    [[nodiscard]] bool operator==(const TransportId&) const = default;
};

enum class TransportTargetKind
{
    Tailgate,
    Derp,
    Peer,
};

struct TransportTarget
{
    TransportTargetKind Kind = TransportTargetKind::Tailgate;
    std::uint32_t Value = 0;
};

class TransportManager
{
public:
    virtual ~TransportManager() = default;

    [[nodiscard]] virtual TransportId Resolve(const TransportTarget& target) const = 0;
    virtual void Reset() = 0;
};

} // namespace tailgate::uwp::bg::manager
