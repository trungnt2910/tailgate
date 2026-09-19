#include "VpnBackgroundTask.h"

#include <exception>
#include <mutex>
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
std::mutex PluginCreationMutex;

namespace background = winrt::Windows::ApplicationModel::Background;
namespace core = winrt::Windows::ApplicationModel::Core;
namespace foundation = winrt::Windows::Foundation;
namespace vpn = winrt::Windows::Networking::Vpn;

class VpnBackgroundTask : public winrt::implements<VpnBackgroundTask, background::IBackgroundTask>
{
public:
    void Run(const background::IBackgroundTaskInstance& taskInstance)
    {
        auto deferral = taskInstance.GetDeferral();
        try
        {
            const foundation::IInspectable triggerDetails = taskInstance.TriggerDetails();
            vpn::IVpnPlugIn plugin{nullptr};
            {
                // Windows can dispatch multiple task instances in a fresh background host.
                // Lookup and insertion must be atomic so every callback uses the same plugin.
                std::lock_guard lock(PluginCreationMutex);
                auto properties = core::CoreApplication::Properties();
                if (properties.HasKey(PluginKey))
                {
                    plugin = properties.Lookup(PluginKey).as<vpn::IVpnPlugIn>();
                }
                else
                {
                    plugin = CreateTailgateVpnPlugin();
                    properties.Insert(PluginKey, plugin);
                    m_logger.LogDebug("created VPN plugin");
                }
            }
            m_logger.LogTrace("VpnChannel::ProcessEventAsync begin instance={} trigger={}",
                              taskInstance.InstanceId(),
                              winrt::get_class_name(triggerDetails));
            vpn::VpnChannel::ProcessEventAsync(plugin, triggerDetails);
            m_logger.LogTrace("VpnChannel::ProcessEventAsync end instance={}",
                              taskInstance.InstanceId());
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
