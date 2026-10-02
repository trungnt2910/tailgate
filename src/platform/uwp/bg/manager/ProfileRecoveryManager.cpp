#include "ProfileRecoveryManager.h"

namespace tailgate::uwp::bg::manager
{

void ProfileRecoveryManager::FinishFailedConnect(const std::function<void()>& terminate)
{
    const bool recovery = Request();
    terminate();
    if (recovery)
    {
        AttemptTerminated();
    }
}

} // namespace tailgate::uwp::bg::manager
