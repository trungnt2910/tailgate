#include "app/ui/ResourceLoader.h"

namespace tailgate::uwp::app
{
namespace resources = winrt::Windows::ApplicationModel::Resources;

ResourceLoader::ResourceLoader() : m_loader(resources::ResourceLoader::GetForCurrentView())
{
}

winrt::hstring ResourceLoader::Get(const ResourceKey& key) const
{
    return m_loader.GetString(winrt::hstring(key.Name));
}

} // namespace tailgate::uwp::app
