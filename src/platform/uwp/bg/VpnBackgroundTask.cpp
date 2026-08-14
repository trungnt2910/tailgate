#include "VpnBackgroundTask.h"

#include <exception>
#include <string_view>

#include <winrt/Windows.ApplicationModel.Background.h>
#include <winrt/Windows.ApplicationModel.Core.h>
#include <winrt/Windows.Networking.Vpn.h>
#include <winrt/base.h>

#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"

#include "plugin/TailgateVpnPlugin.h"

namespace tailgate::uwp::bg
{
namespace
{

constexpr std::wstring_view PluginKey = L"TailgateVpnPlugin";

namespace background = winrt::Windows::ApplicationModel::Background;
namespace core = winrt::Windows::ApplicationModel::Core;
namespace foundation = winrt::Windows::Foundation;
namespace vpn = winrt::Windows::Networking::Vpn;

struct VpnBackgroundTask : winrt::implements<VpnBackgroundTask, background::IBackgroundTask>
{
    void Run(const background::IBackgroundTaskInstance& taskInstance)
    {
        m_logger.LogDebug("VpnBackgroundTask.Run entered instance={}", taskInstance.InstanceId());
        auto deferral = taskInstance.GetDeferral();
        try
        {
            const foundation::IInspectable triggerDetails = taskInstance.TriggerDetails();
            auto properties = core::CoreApplication::Properties();
            vpn::IVpnPlugIn plugin{nullptr};
            if (properties.HasKey(PluginKey))
            {
                plugin = properties.Lookup(PluginKey).as<vpn::IVpnPlugIn>();
            }
            else
            {
                plugin = CreateTailgateVpnPlugin();
                properties.Insert(PluginKey, plugin);
            }
            m_logger.LogDebug("VpnChannel::ProcessEventAsync begin trigger={}",
                              winrt::get_class_name(triggerDetails));
            vpn::VpnChannel::ProcessEventAsync(plugin, triggerDetails);
            m_logger.LogDebug("VpnChannel::ProcessEventAsync end");
        }
        catch (const winrt::hresult_error& error)
        {
            m_logger.LogError("VpnBackgroundTask.Run failed hresult={} message={}",
                              error.code(),
                              error.message());
        }
        catch (const std::exception& error)
        {
            m_logger.LogError("VpnBackgroundTask.Run failed message={}", error.what());
        }
        catch (...)
        {
            m_logger.LogError("VpnBackgroundTask.Run failed with an unknown exception");
        }
        deferral.Complete();
    }

private:
    tailgate::base::Logger m_logger{"uwp-background-task"};
};

} // namespace

foundation::IInspectable CreateVpnBackgroundTask()
{
    return winrt::make<VpnBackgroundTask>();
}

} // namespace tailgate::uwp::bg
