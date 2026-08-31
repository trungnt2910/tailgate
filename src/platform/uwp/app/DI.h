#pragma once

#include <tailgate/di/Bindings.h>

namespace tailgate::uwp
{

using AppInjector = tailgate::di::Injector;

// The function-local instance is initialized on first use. Callers must not resolve dependencies
// from namespace-scope initializers.
[[nodiscard]] AppInjector& GetDI();

} // namespace tailgate::uwp
