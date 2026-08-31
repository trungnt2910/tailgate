#pragma once

#include <memory>
#include <type_traits>

#ifndef BOOST_DI_CFG_CTOR_LIMIT_SIZE
#define BOOST_DI_CFG_CTOR_LIMIT_SIZE 32
#endif
#include <boost/di/extension/injector.hpp>

namespace tailgate::di
{

class Injector final : public boost::di::extension::injector<>
{
public:
    Injector() = default;
    Injector(const Injector&) = delete;
    Injector& operator=(const Injector&) = delete;
    Injector(Injector&&) = delete;
    Injector& operator=(Injector&&) = delete;

    template <class TImplementation, class... TAbstractions>
    void InstallSingleton()
    {
        static_assert((std::is_base_of_v<TAbstractions, TImplementation> && ...));
        this->install(boost::di::bind<TImplementation>.template to<TImplementation>().in(
            boost::di::singleton));
        const std::shared_ptr<TImplementation> implementation =
            this->template create<std::shared_ptr<TImplementation>>();
        // The injector owns the object from now on.
        ((this->cfg().template data<TAbstractions>() =
              std::static_pointer_cast<TAbstractions>(implementation)),
         ...);
    }
};

void InstallCoreBindings(Injector& injector);

} // namespace tailgate::di
