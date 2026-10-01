#include "ExitNodeChangeResult.h"

#include <cstdint>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.h>

#include "Settings.h"

namespace tailgate::uwp
{
namespace
{

constexpr wchar_t ResultSetting[] = L"ExitNodeChangeResult";

}

void ExitNodeChangeResult::Publish(const app_service::ExitNodeResponse& response)
{
    winrt::Windows::Storage::ApplicationDataCompositeValue value;
    value.Insert(L"Sequence", winrt::box_value(response.Sequence));
    value.Insert(L"Result", winrt::box_value(static_cast<std::uint32_t>(response.Result)));
    value.Insert(L"ExitNode", winrt::box_value(winrt::to_hstring(response.ExitNode)));
    Settings::Set(ResultSetting, value);
    winrt::Windows::Storage::ApplicationData::Current().SignalDataChanged();
}

std::optional<app_service::ExitNodeResponse> ExitNodeChangeResult::Read()
{
    const auto value = Settings::Get(ResultSetting)
                           .try_as<winrt::Windows::Storage::ApplicationDataCompositeValue>();
    if (!value)
    {
        return std::nullopt;
    }
    return app_service::ExitNodeResponse{
        .Result = static_cast<app_service::Status>(
            winrt::unbox_value<std::uint32_t>(value.Lookup(L"Result"))),
        .Sequence = winrt::unbox_value<std::uint64_t>(value.Lookup(L"Sequence")),
        .ExitNode = winrt::to_string(winrt::unbox_value<winrt::hstring>(value.Lookup(L"ExitNode"))),
    };
}

} // namespace tailgate::uwp
