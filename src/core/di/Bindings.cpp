#include <tailgate/di/Bindings.h>

namespace tailgate::di
{

CoreBindings Bindings()
{
    namespace boost_di = boost::di;
    return boost_di::bind<tailgate::base::IClock>.to<tailgate::base::SteadyClock>().in(
        boost_di::extension::scoped);
}

} // namespace tailgate::di
