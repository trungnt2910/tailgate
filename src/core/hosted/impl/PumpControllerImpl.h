#pragma once

#include <tailgate/hosted/PumpController.h>

namespace tailgate::hosted::impl
{

class PumpControllerImpl final : public PumpController
{
public:
    explicit PumpControllerImpl(tailgate::base::TimeProvider& timeProvider) noexcept;
    [[nodiscard]] std::optional<PumpSchedule> Update(bool localOutputPending,
                                                     std::optional<TimePoint> deadline) override;
    void Complete(std::uint64_t requestId) noexcept override;
    void Reset() noexcept override;

private:
    tailgate::base::TimeProvider& m_timeProvider;
    std::optional<TimePoint> m_deadline;
    std::uint64_t m_nextRequestId = 1;
    std::uint64_t m_pendingRequestId = 0;
    bool m_immediate = false;
};

} // namespace tailgate::hosted::impl
