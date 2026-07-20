#pragma once

#include <cstddef>
#include <optional>
#include <utility>

#include "app/controller/AuthorizationController.h"

namespace tailgate::uwp::tests
{

class FakeAuthorizationController final : public AuthorizationController
{
public:
    [[nodiscard]] const AuthorizationControllerState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] AuthorizationControllerState& GetState() noexcept
    {
        return m_state;
    }

    void SetPendingAuthentication(const winrt::hstring& server,
                                  const winrt::hstring& authKey) override
    {
        ++SetPendingAuthenticationCount;
        m_state.PendingTailgateServer(server);
        m_state.PendingAuthKey(authKey);
    }

    void AcceptAuthentication() override
    {
        ++AcceptAuthenticationCount;
    }

    void ClearPendingAuthentication() override
    {
        ++ClearPendingAuthenticationCount;
        m_state.PendingTailgateServer({});
        m_state.PendingAuthKey({});
        m_state.PendingHostname(std::nullopt);
    }

    void Cache(AuthorizationCache authorization) override
    {
        ++CacheCount;
        m_state.Authorization(std::move(authorization));
    }

    void FindCached(const winrt::hstring&, const winrt::hstring&, const winrt::hstring&) override
    {
        ++FindCachedCount;
    }

    void RequestPrompt(const winrt::hstring& url, bool machineApproval) override
    {
        ++RequestPromptCount;
        m_state.PromptUrl(url);
        m_state.MachineApproval(machineApproval);
    }

    void Clear() override
    {
        ++ClearCount;
        m_state.PromptUrl({});
    }

    std::size_t SetPendingAuthenticationCount = 0;
    std::size_t AcceptAuthenticationCount = 0;
    std::size_t ClearPendingAuthenticationCount = 0;
    std::size_t CacheCount = 0;
    std::size_t FindCachedCount = 0;
    std::size_t RequestPromptCount = 0;
    std::size_t ClearCount = 0;

private:
    AuthorizationControllerState m_state;
};

} // namespace tailgate::uwp::tests
