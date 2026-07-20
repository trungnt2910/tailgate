#pragma once

#include <memory>

#include "app/controller/PingController.h"

namespace tailgate::uwp
{

struct PingSessionState;

class PingControllerImpl final : public PingController
{
public:
    ~PingControllerImpl() override;

    [[nodiscard]] const PingState& GetState() const noexcept override;
    void Start(const winrt::hstring& address, const winrt::hstring& selfAddress) override;
    void Stop() noexcept override;

private:
    PingState m_state;
    std::shared_ptr<PingSessionState> m_session;
};

} // namespace tailgate::uwp
