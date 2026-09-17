#include "ServiceBase.h"

namespace tailgate::uwp::bg::service
{

std::optional<tailgate::base::TimeProvider::TimePoint> ServiceBase::NextDeadline() const
{
    return std::nullopt;
}

void ServiceBase::AppendRelayFrame(std::vector<std::uint8_t>& output,
                                   const tailgate::hosted::Frame& frame)
{
    std::vector<std::uint8_t> encoded = frame.Encode();
    output.insert(output.end(), encoded.begin(), encoded.end());
}

} // namespace tailgate::uwp::bg::service
