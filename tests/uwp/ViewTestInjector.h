#pragma once

#include <memory>
#include <utility>

#define BOOST_DI_CFG_CTOR_LIMIT_SIZE 32
#include <boost/di.hpp>

#include "app/ui/AppResources.h"
#include "app/ui/ButtonFactory.h"
#include "app/ui/ResourceLoader.h"
#include "app/ui/UiFactory.h"

namespace tailgate::uwp::tests
{

namespace di = boost::di;

class ViewTestInjector final
{
public:
    void Initialize()
    {
        m_resources = std::make_shared<AppResources>();
        m_buttonFactory = std::make_shared<ButtonFactory>(*m_resources);
        m_uiFactory = std::make_shared<UiFactory>(*m_resources);
        m_resourceLoader = std::make_shared<app::ResourceLoader>();
    }

    template <typename Type, typename... Bindings>
    [[nodiscard]] std::unique_ptr<Type> Create(Bindings&&... bindings)
    {
        auto injector = di::make_injector(di::bind<AppResources>.to(
                                              [this](const auto&) -> AppResources&
                                              {
                                                  return *m_resources;
                                              }),
                                          di::bind<ButtonFactory>.to(
                                              [this](const auto&) -> ButtonFactory&
                                              {
                                                  return *m_buttonFactory;
                                              }),
                                          di::bind<UiFactory>.to(
                                              [this](const auto&) -> UiFactory&
                                              {
                                                  return *m_uiFactory;
                                              }),
                                          di::bind<ResourceLoader>.to(
                                              [this](const auto&) -> ResourceLoader&
                                              {
                                                  return *m_resourceLoader;
                                              }),
                                          std::forward<Bindings>(bindings)...);
        return injector.template create<std::unique_ptr<Type>>();
    }

private:
    std::shared_ptr<AppResources> m_resources;
    std::shared_ptr<ButtonFactory> m_buttonFactory;
    std::shared_ptr<UiFactory> m_uiFactory;
    std::shared_ptr<app::ResourceLoader> m_resourceLoader;
};

} // namespace tailgate::uwp::tests
