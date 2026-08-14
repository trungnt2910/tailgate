#pragma once

#include <tailgate/base/Logger.h>

#include "common/UwpFireAndForget.h"
#include "common/UwpFormat.h"

#include "app/controller/TailgateRelayController.h"

namespace tailgate::uwp
{

class TailgateRelayControllerImpl final : public TailgateRelayController
{
public:
    [[nodiscard]] const TailgateRelayState& GetState() const noexcept override;
    void Preflight(std::uint64_t operationId, const winrt::hstring& tailgateServer) override;

private:
    FireAndForget PreflightInBackground(std::uint64_t operationId, winrt::hstring tailgateServer);

    TailgateRelayState m_state;
    tailgate::base::Logger m_logger{"uwp-tailgate-relay-ctrl"};
};

} // namespace tailgate::uwp
