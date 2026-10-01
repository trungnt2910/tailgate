#pragma once

#include <cstdint>
#include <vector>

#include "service/IService.h"

namespace tailgate::uwp::bg::service
{

class ServiceBase : public IService
{
public:
    [[nodiscard]] std::optional<tailgate::base::TimeProvider::TimePoint>
    NextDeadline() const override;
};

} // namespace tailgate::uwp::bg::service
