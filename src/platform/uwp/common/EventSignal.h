#pragma once

#include <winrt/base.h>

#include <tailgate/Logger.h>

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
    Logger m_logger{"uwp-event-signal"};
};

} // namespace tailgate::uwp
