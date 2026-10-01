#include "ServiceBase.h"

namespace tailgate::uwp::bg::service
{

std::optional<tailgate::base::TimeProvider::TimePoint> ServiceBase::NextDeadline() const
{
    return std::nullopt;
}

} // namespace tailgate::uwp::bg::service
