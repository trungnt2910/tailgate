#pragma once

#include <optional>

#include "UwpAppServiceProtocol.h"

namespace tailgate::uwp
{

// A channel restart can invalidate the foreground's in-tunnel reply socket.
// Retain the sequenced completion until the next change or account cleanup.
class ExitNodeChangeResult final
{
public:
    static void Publish(const app_service::ExitNodeResponse& response);
    [[nodiscard]] static std::optional<app_service::ExitNodeResponse> Read();
};

} // namespace tailgate::uwp
