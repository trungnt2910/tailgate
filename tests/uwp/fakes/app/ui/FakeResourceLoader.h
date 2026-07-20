#pragma once

#include <map>
#include <string>

#include "common/ResourceLoader.h"

namespace tailgate::uwp::tests
{

class FakeResourceLoader final : public ResourceLoader
{
public:
    [[nodiscard]] winrt::hstring Get(const ResourceKey& key) const override
    {
        const auto value = Values.find(key.Name);
        return value == Values.end() ? winrt::hstring(key.Name) : value->second;
    }

    std::map<std::wstring, winrt::hstring, std::less<>> Values;
};

} // namespace tailgate::uwp::tests
