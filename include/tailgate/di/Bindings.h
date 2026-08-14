#pragma once

#include <boost/di.hpp>
#include <boost/di/extension/scopes/scoped.hpp>

#include <tailgate/base/Clock.h>

namespace tailgate::di
{

using CoreBindings =
    decltype(boost::di::bind<tailgate::base::IClock>.to<tailgate::base::SteadyClock>().in(
        boost::di::extension::scoped));

[[nodiscard]] CoreBindings Bindings();

} // namespace tailgate::di
