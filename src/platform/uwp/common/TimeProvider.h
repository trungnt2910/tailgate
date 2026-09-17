#pragma once

#include <memory>

#include <winrt/Windows.System.Threading.h>

#include <tailgate/base/Logger.h>
#include <tailgate/base/TimeProvider.h>

#include "EventSignal.h"

namespace tailgate::uwp
{

class WaitToken final : public base::WaitToken
{
public:
    explicit WaitToken(base::TimeProvider::TimePoint deadline);
    ~WaitToken() override;

    [[nodiscard]] void* Handle() const noexcept;

private:
    std::shared_ptr<EventSignal> m_signal;
    winrt::Windows::System::Threading::ThreadPoolTimer m_timer{nullptr};
    base::Logger m_logger{"uwp-wait-token"};
};

class TimeProvider final : public base::TimeProvider
{
public:
    [[nodiscard]] TimePoint Now() const noexcept override;
    [[nodiscard]] std::unique_ptr<base::WaitToken> At(TimePoint timePoint) override;
};

} // namespace tailgate::uwp
