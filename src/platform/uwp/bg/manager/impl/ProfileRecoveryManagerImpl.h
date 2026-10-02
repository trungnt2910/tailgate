#pragma once

#include <memory>

#include "manager/ProfileRecoveryManager.h"

namespace tailgate::uwp::bg::manager
{

struct ProfileRecoveryCoordinator;

class ProfileRecoveryManagerImpl final : public ProfileRecoveryManager
{
public:
    ProfileRecoveryManagerImpl();
    ~ProfileRecoveryManagerImpl() override;
    void EnterConnect() override;
    void LeaveConnect() override;
    [[nodiscard]] bool Request() override;
    void AttemptTerminated() override;
    void RunPending(std::stop_token cancellation) override;
    void Disconnecting() override;
    void Connected() override;

private:
    std::unique_ptr<ProfileRecoveryCoordinator> m_coordinator;
};

} // namespace tailgate::uwp::bg::manager
