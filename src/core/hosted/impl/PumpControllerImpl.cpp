#include "PumpControllerImpl.h"

#include <algorithm>
#include <chrono>
#include <limits>

namespace tailgate::hosted::impl
{

PumpControllerImpl::PumpControllerImpl(tailgate::base::TimeProvider& timeProvider) noexcept
    : m_timeProvider(timeProvider)
{
}

std::optional<PumpSchedule> PumpControllerImpl::Update(bool localOutputPending,
                                                       std::optional<TimePoint> deadline)
{
    if (deadline)
    {
        // The protocol carries millisecond delays. Sub-millisecond clock sampling jitter
        // must not turn ordinary packet callbacks into repeated schedule messages.
        deadline = std::chrono::ceil<std::chrono::milliseconds>(*deadline);
    }
    if (m_pendingRequestId != 0 &&
        ((localOutputPending && m_immediate) ||
         (!localOutputPending && !m_immediate && deadline == m_deadline)))
    {
        return std::nullopt;
    }
    if (!localOutputPending && !deadline && m_pendingRequestId == 0)
    {
        return std::nullopt;
    }
    if (m_nextRequestId == std::numeric_limits<std::uint64_t>::max())
    {
        throw PumpException(PumpError::RequestIdExhausted);
    }
    PumpSchedule result;
    result.RequestId = m_nextRequestId++;
    if (localOutputPending)
    {
        result.Delay = std::chrono::milliseconds::zero();
    }
    else if (deadline)
    {
        result.Delay = std::clamp(
            std::chrono::ceil<std::chrono::milliseconds>(*deadline - m_timeProvider.Now()),
            std::chrono::milliseconds::zero(),
            MaximumPumpDelay);
    }
    m_pendingRequestId = result.Delay ? result.RequestId : 0;
    m_immediate = localOutputPending;
    m_deadline = deadline;
    return result;
}

void PumpControllerImpl::Complete(std::uint64_t requestId) noexcept
{
    if (requestId == m_pendingRequestId)
    {
        m_pendingRequestId = 0;
        m_deadline.reset();
        m_immediate = false;
    }
}

void PumpControllerImpl::Reset() noexcept
{
    m_pendingRequestId = 0;
    m_deadline.reset();
    m_immediate = false;
    // Keep identifiers monotonic so an old callback cannot complete a newly scheduled request.
}

} // namespace tailgate::hosted::impl
