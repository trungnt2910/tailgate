#pragma once

#include <cstdint>
#include <optional>

#include <tailgate/base/TimeProvider.h>
#include <tailgate/hosted/Pump.h>

namespace tailgate::hosted
{

class PumpController
{
public:
    using TimePoint = tailgate::base::TimeProvider::TimePoint;

    virtual ~PumpController();
    [[nodiscard]] virtual std::optional<PumpSchedule> Update(bool localOutputPending,
                                                             std::optional<TimePoint> deadline) = 0;
    virtual void Complete(std::uint64_t requestId) noexcept = 0;
    virtual void Reset() noexcept = 0;

protected:
    PumpController() = default;
};

} // namespace tailgate::hosted
