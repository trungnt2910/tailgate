#pragma once

#include <cstddef>
#include <optional>

#include "app/controller/PingController.h"

namespace tailgate::uwp::tests
{

struct PingStartCall final
{
    winrt::hstring address;
    winrt::hstring selfAddress;
};

class FakePingController final : public PingController
{
public:
    using Interface = PingController;

    [[nodiscard]] const PingState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] PingState& GetState() noexcept
    {
        return m_state;
    }

    void Start(const winrt::hstring& address, const winrt::hstring& selfAddress) override
    {
        StartCall = PingStartCall{.address = address, .selfAddress = selfAddress};
    }

    void Stop() noexcept override
    {
        ++StopCount;
    }

    std::optional<PingStartCall> StartCall;
    std::size_t StopCount = 0;

private:
    PingState m_state;
};

} // namespace tailgate::uwp::tests
