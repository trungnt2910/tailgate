#pragma once

#include "manager/TransportManager.h"

namespace tailgate::uwp::bg::manager
{

class Rs2TransportManagerImpl final : public TransportManager
{
public:
    [[nodiscard]] TransportId Resolve(const TransportTarget& target) const override;
    void Reset() override;
};

} // namespace tailgate::uwp::bg::manager
