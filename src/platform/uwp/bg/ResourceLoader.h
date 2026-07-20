#pragma once

#include <winrt/Windows.ApplicationModel.Resources.h>

#include "common/ResourceLoader.h"

namespace tailgate::uwp::bg
{

class ResourceLoader final : public tailgate::uwp::ResourceLoader
{
public:
    ResourceLoader();

    [[nodiscard]] winrt::hstring Get(const ResourceKey& key) const override;

private:
    winrt::Windows::ApplicationModel::Resources::ResourceLoader m_loader;
};

} // namespace tailgate::uwp::bg
