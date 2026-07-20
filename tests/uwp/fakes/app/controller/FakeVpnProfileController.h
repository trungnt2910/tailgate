#pragma once

#include <cstddef>
#include <optional>
#include <utility>

#include "app/controller/VpnProfileController.h"

namespace tailgate::uwp::tests
{

class FakeVpnProfileController final : public VpnProfileController
{
public:
    [[nodiscard]] const VpnProfileState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] VpnProfileState& GetState() noexcept
    {
        return m_state;
    }

    void Connect(winrt::hstring server, winrt::hstring, bool) override
    {
        ConnectServer = std::move(server);
    }

    void CancelConnect() override
    {
        ++CancelConnectCount;
    }

    void Disconnect() override
    {
        ++DisconnectCount;
    }

    void Logout() override
    {
        ++LogoutCount;
    }

    void DiscardProfile() override
    {
        ++DiscardProfileCount;
    }

    void Refresh() override
    {
        ++RefreshCount;
    }

    std::optional<winrt::hstring> ConnectServer;
    std::size_t CancelConnectCount = 0;
    std::size_t DisconnectCount = 0;
    std::size_t LogoutCount = 0;
    std::size_t DiscardProfileCount = 0;
    std::size_t RefreshCount = 0;

private:
    VpnProfileState m_state;
};

} // namespace tailgate::uwp::tests
