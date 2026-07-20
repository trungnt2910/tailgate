#pragma once

#include <winrt/Windows.ApplicationModel.Activation.h>
#include <winrt/Windows.ApplicationModel.Background.h>
#include <winrt/Windows.ApplicationModel.Core.h>
#include <winrt/Windows.ApplicationModel.DataTransfer.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Networking.Vpn.h>
#include <winrt/Windows.Networking.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.UI.Text.h>
#include <winrt/Windows.UI.Xaml.Controls.Primitives.h>
#include <winrt/Windows.UI.Xaml.Controls.h>
#include <winrt/Windows.UI.Xaml.Data.h>
#include <winrt/Windows.UI.Xaml.Markup.h>
#include <winrt/Windows.UI.Xaml.Media.h>
#include <winrt/Windows.UI.Xaml.Shapes.h>
#include <winrt/Windows.UI.Xaml.h>
#include <winrt/Windows.UI.h>

namespace tailgate::uwp
{

namespace activation = winrt::Windows::ApplicationModel::Activation;
namespace appmodel = winrt::Windows::ApplicationModel;
namespace background = winrt::Windows::ApplicationModel::Background;
namespace collections = winrt::Windows::Foundation::Collections;
namespace core = winrt::Windows::ApplicationModel::Core;
namespace controls = winrt::Windows::UI::Xaml::Controls;
namespace datatransfer = winrt::Windows::ApplicationModel::DataTransfer;
namespace foundation = winrt::Windows::Foundation;
namespace media = winrt::Windows::UI::Xaml::Media;
namespace networking = winrt::Windows::Networking;
namespace shapes = winrt::Windows::UI::Xaml::Shapes;
namespace storage = winrt::Windows::Storage;
namespace text = winrt::Windows::UI::Text;
namespace ui = winrt::Windows::UI;
namespace vpn = winrt::Windows::Networking::Vpn;
namespace xaml = winrt::Windows::UI::Xaml;
namespace xaml_data = winrt::Windows::UI::Xaml::Data;
namespace xaml_markup = winrt::Windows::UI::Xaml::Markup;

} // namespace tailgate::uwp
