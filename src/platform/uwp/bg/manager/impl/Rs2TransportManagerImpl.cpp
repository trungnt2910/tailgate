#include "Rs2TransportManagerImpl.h"

namespace tailgate::uwp::bg::manager
{

TransportId Rs2TransportManagerImpl::Resolve(const TransportTarget&) const
{
    return TransportId{.Value = 0};
}

void Rs2TransportManagerImpl::Reset()
{
}

} // namespace tailgate::uwp::bg::manager
