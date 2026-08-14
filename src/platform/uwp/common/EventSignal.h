#pragma once

#include <winrt/base.h>

#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"

namespace tailgate::uwp
{

class EventSignal final
{
public:
    EventSignal();

    [[nodiscard]] void* Handle() const noexcept;
    void Set() const noexcept;

private:
    winrt::handle m_signal;
    tailgate::base::Logger m_logger{"uwp-event-signal"};
};

} // namespace tailgate::uwp
