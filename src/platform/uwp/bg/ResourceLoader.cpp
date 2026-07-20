#include "bg/ResourceLoader.h"

namespace tailgate::uwp::bg
{
namespace resources = winrt::Windows::ApplicationModel::Resources;

ResourceLoader::ResourceLoader() : m_loader(resources::ResourceLoader::GetForViewIndependentUse())
{
}

winrt::hstring ResourceLoader::Get(const ResourceKey& key) const
{
    return m_loader.GetString(winrt::hstring(key.Name));
}

} // namespace tailgate::uwp::bg
