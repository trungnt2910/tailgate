#include "app/controller/impl/ClipboardControllerImpl.h"

#include <winrt/Windows.ApplicationModel.DataTransfer.h>

namespace tailgate::uwp
{

void ClipboardControllerImpl::SetText(const winrt::hstring& value)
{
    winrt::Windows::ApplicationModel::DataTransfer::DataPackage package;
    package.SetText(value);
    winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(package);
}

} // namespace tailgate::uwp
