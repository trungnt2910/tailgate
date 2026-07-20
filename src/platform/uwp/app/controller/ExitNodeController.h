#pragma once

#include "app/model/ExitNodeState.h"
#include "common/UwpAliases.h"

namespace tailgate::uwp
{

class ExitNodeController
{
public:
    virtual ~ExitNodeController() = default;

    [[nodiscard]] virtual const ExitNodeState& GetState() const noexcept = 0;
    virtual void Reload() = 0;
    virtual void SetNode(const winrt::hstring& nodeName) = 0;
    virtual void SetNodeForNextConnection(const winrt::hstring& nodeName) = 0;
    virtual void SetEnabled(bool enabled) = 0;
};

} // namespace tailgate::uwp
