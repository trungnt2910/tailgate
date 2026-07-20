#pragma once

#include "app/model/AuthorizationControllerState.h"

namespace tailgate::uwp
{

class AuthorizationController
{
public:
    virtual ~AuthorizationController() = default;

    [[nodiscard]] virtual const AuthorizationControllerState& GetState() const noexcept = 0;
    virtual void SetPendingAuthentication(const winrt::hstring& tailgateServer,
                                          const winrt::hstring& authKey) = 0;
    virtual void AcceptAuthentication() = 0;
    virtual void ClearPendingAuthentication() = 0;
    virtual void Cache(AuthorizationCache authorization) = 0;
    virtual void FindCached(const winrt::hstring& tailgateServer,
                            const winrt::hstring& authKey,
                            const winrt::hstring& hostname) = 0;
    virtual void RequestPrompt(const winrt::hstring& url, bool machineApproval) = 0;
    virtual void Clear() = 0;
};

} // namespace tailgate::uwp
