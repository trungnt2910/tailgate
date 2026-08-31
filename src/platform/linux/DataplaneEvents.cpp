#include "DataplaneEvents.h"

namespace tailgate::linux_frontend
{

std::uint64_t DataplaneEvent::Value() const noexcept
{
    return (static_cast<std::uint64_t>(m_kind) << DataplaneEvent::KindShift) | m_index;
}

tailgate::base::EventToken DataplaneEvent::Token() const noexcept
{
    return tailgate::base::EventToken{.Value = Value()};
}

DataplaneEvent DataplaneEvent::FromValue(std::uint64_t value) noexcept
{
    return DataplaneEvent(static_cast<Kind>(value >> DataplaneEvent::KindShift),
                          static_cast<std::uint32_t>(value));
}

} // namespace tailgate::linux_frontend
