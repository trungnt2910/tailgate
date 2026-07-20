#include "VpnBackgroundTask.h"

#include <string_view>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <hstring.h>
#include <winstring.h>

#include <winrt/Windows.Foundation.h>
#include <winrt/base.h>

#include <tailgate/Logger.h>

#include "common/UwpFormat.h"
#include "common/UwpLogger.h"

namespace
{

constexpr std::wstring_view BackgroundTaskClassName = L"Tailgate.Background.TailgateVpnTask";
constexpr wchar_t LogFileName[] = L"Tailgate.Background.log";
tailgate::Logger BackgroundLogger{"uwp-background"};

namespace foundation = winrt::Windows::Foundation;

struct TailgateActivationFactory
    : winrt::implements<TailgateActivationFactory, foundation::IActivationFactory>
{
    winrt::Windows::Foundation::IInspectable ActivateInstance()
    {
        m_logger.LogDebug("TailgateActivationFactory.ActivateInstance");
        return tailgate::uwp::bg::CreateVpnBackgroundTask();
    }

private:
    tailgate::Logger m_logger{"uwp-background-factory"};
};

} // namespace

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD, void*)
{
    return TRUE;
}

extern "C" HRESULT WINAPI DllCanUnloadNow()
{
    return winrt::get_module_lock() ? S_FALSE : S_OK;
}

extern "C" HRESULT WINAPI DllGetActivationFactory(HSTRING classId, void** factory)
{
    tailgate::uwp::InstallUwpLogSink(LogFileName);
    if (factory == nullptr)
    {
        BackgroundLogger.LogError("DllGetActivationFactory received a null output pointer");
        return E_POINTER;
    }
    *factory = nullptr;

    const winrt::hstring name{WindowsGetStringRawBuffer(classId, nullptr)};
    BackgroundLogger.LogDebug("DllGetActivationFactory class={}", name);
    if (name != BackgroundTaskClassName)
    {
        return winrt::hresult_class_not_available(name).to_abi();
    }

    auto result = winrt::make<TailgateActivationFactory>();
    *factory = winrt::detach_abi(result);
    return S_OK;
}
