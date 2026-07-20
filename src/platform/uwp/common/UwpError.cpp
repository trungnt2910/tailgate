#include "common/UwpError.h"

#include "strings/Resources.h"

namespace tailgate::uwp
{

const ResourceKey& UwpError::Resource(Code error) noexcept
{
    switch (error)
    {
    case Code::RelayConnectionFailed:
        return Resources::Error::RelayConnectionFailed;
    case Code::ConnectionCancelled:
        return Resources::Error::ConnectionCancelled;
    case Code::VpnServerRequired:
        return Resources::Error::VpnServerRequired;
    case Code::VpnServerInvalid:
        return Resources::Error::VpnServerInvalid;
    case Code::VpnProfileTransitionTimedOut:
        return Resources::Error::VpnProfileTransitionTimedOut;
    case Code::VpnProfileOperationFailed:
        return Resources::Error::VpnProfileOperationFailed;
    case Code::VpnProfileDidNotConnect:
        return Resources::Error::VpnProfileDidNotConnect;
    case Code::VpnDisconnectFailed:
        return Resources::Error::VpnDisconnectFailed;
    case Code::VpnLogoutFailed:
        return Resources::Error::VpnLogoutFailed;
    case Code::PreviousConnectionRestoreFailed:
        return Resources::Error::PreviousConnectionRestoreFailed;
    case Code::DeviceApprovalRequired:
        return Resources::Error::DeviceApprovalRequired;
    case Code::DeviceAuthorizationRequired:
        return Resources::Error::DeviceAuthorizationRequired;
    case Code::VpnAddressUnavailable:
        return Resources::Error::VpnAddressUnavailable;
    case Code::VpnBackgroundRestartTimedOut:
        return Resources::Error::VpnBackgroundRestartTimedOut;
    case Code::ExitNodeRejected:
        return Resources::Error::ExitNodeRejected;
    case Code::ExitNodeFailed:
        return Resources::Error::ExitNodeFailed;
    case Code::None:
    case Code::Unexpected:
        return Resources::Error::Unexpected;
    }
    return Resources::Error::Unexpected;
}

} // namespace tailgate::uwp
