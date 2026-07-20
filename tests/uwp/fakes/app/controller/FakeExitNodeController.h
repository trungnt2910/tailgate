#pragma once

#include <cstddef>
#include <optional>

#include "app/controller/ExitNodeController.h"

namespace tailgate::uwp::tests
{

class FakeExitNodeController final : public ExitNodeController
{
public:
    using Interface = ExitNodeController;

    [[nodiscard]] const ExitNodeState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] ExitNodeState& GetState() noexcept
    {
        return m_state;
    }

    void Reload() override
    {
        ++ReloadCount;
    }

    void SetNode(const winrt::hstring& nodeName) override
    {
        SetNodeArgument = nodeName;
    }

    void SetNodeForNextConnection(const winrt::hstring& nodeName) override
    {
        SetNodeForNextConnectionArgument = nodeName;
    }

    void SetEnabled(bool enabled) override
    {
        SetEnabledArgument = enabled;
    }

    std::size_t ReloadCount = 0;
    std::optional<winrt::hstring> SetNodeArgument;
    std::optional<winrt::hstring> SetNodeForNextConnectionArgument;
    std::optional<bool> SetEnabledArgument;

private:
    ExitNodeState m_state;
};

} // namespace tailgate::uwp::tests
