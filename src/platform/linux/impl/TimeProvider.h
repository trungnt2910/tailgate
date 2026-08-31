#pragma once

#include <memory>

#include <tailgate/base/TimeProvider.h>

#include "UniqueFd.h"

namespace tailgate::linux_frontend::impl
{

class WaitToken final : public tailgate::base::WaitToken
{
public:
    explicit WaitToken(UniqueFd descriptor) noexcept;

    [[nodiscard]] int Descriptor() const noexcept;

private:
    UniqueFd m_descriptor;
};

class TimeProvider final : public tailgate::base::TimeProvider
{
public:
    [[nodiscard]] TimePoint Now() const noexcept override;
    [[nodiscard]] std::unique_ptr<tailgate::base::WaitToken> At(TimePoint timePoint) override;
};

} // namespace tailgate::linux_frontend::impl
