#pragma once

#include <memory>

#include <tailgate/base/TimeProvider.h>

namespace tailgate::uwp
{

class WaitToken final : public base::WaitToken
{
public:
    explicit WaitToken(base::TimeProvider::TimePoint deadline);
    ~WaitToken() override;

    [[nodiscard]] void* Handle() const noexcept;

private:
    class State;
    std::shared_ptr<State> m_state;
};

class TimeProvider final : public base::TimeProvider
{
public:
    [[nodiscard]] TimePoint Now() const noexcept override;
    [[nodiscard]] std::unique_ptr<base::WaitToken> At(TimePoint timePoint) override;
};

} // namespace tailgate::uwp
