#pragma once

#include <memory>

#include <tailgate/base/TimeProvider.h>

#include "app/controller/ModeRpcController.h"
#include "common/UwpFireAndForget.h"

namespace tailgate::uwp
{

class ModeRpcOperation;

class ModeRpcControllerImpl final : public ModeRpcController
{
public:
    explicit ModeRpcControllerImpl(tailgate::base::TimeProvider& time);
    ~ModeRpcControllerImpl() override;
    [[nodiscard]] const ModeRpcState& GetState() const noexcept override;
    void Request(const winrt::hstring& selfAddress, const winrt::hstring& relayUrl) override;

private:
    FireAndForget Run(winrt::hstring selfAddress,
                      winrt::hstring relayUrl,
                      std::shared_ptr<ModeRpcOperation> operation);
    tailgate::base::TimeProvider& m_time;
    ModeRpcState m_state;
    std::shared_ptr<ModeRpcOperation> m_operation;
};

} // namespace tailgate::uwp
