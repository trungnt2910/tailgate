#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#define WIN32_MEAN_AND_LEAN
#include <windows.h>
#ifdef GetCurrentTime
#undef GetCurrentTime
#endif

#include <winrt/base.h>

#include <tailgate/base/Logger.h>
#include <tailgate/cli/Arguments.h>

#include "common/Arguments.h"
#include "common/UwpFormat.h"
#include "common/UwpLogger.h"

#include "app/DI.h"
#include "app/controller/MainWindowController.h"
#include "app/ui/AppResources.h"
#include "app/view/MainWindowView.h"

namespace
{

constexpr wchar_t LogFileName[] = L"Tailgate.log";

} // namespace

namespace winrt::Tailgate::implementation
{

struct App : tailgate::uwp::xaml::ApplicationT<App>
{
    App()
    {
        tailgate::uwp::InstallUwpLogSink(LogFileName);
        UnhandledException(
            [this](const tailgate::uwp::foundation::IInspectable&,
                   const tailgate::uwp::xaml::UnhandledExceptionEventArgs& args) noexcept
            {
                try
                {
                    m_logger.LogError("unhandled XAML exception hresult={} message={}",
                                      args.Exception(),
                                      args.Message());
                }
                catch (...)
                {
                }
            });
    }

    void OnLaunched(const tailgate::uwp::activation::LaunchActivatedEventArgs&)
    {
        m_logger.LogDebug("launched");
        EnsureResources();
        View().Show();
    }

    void OnActivated(const tailgate::uwp::activation::IActivatedEventArgs& args)
    {
        EnsureResources();
        std::optional<tailgate::cli::Arguments> arguments;
        if (args.Kind() == tailgate::uwp::activation::ActivationKind::Protocol)
        {
            const auto protocolArgs =
                args.as<tailgate::uwp::activation::ProtocolActivatedEventArgs>();
            const auto uri = protocolArgs.Uri();
            const std::vector<std::string> protocolArguments =
                tailgate::uwp::Arguments::FromUri(uri);
            m_logger.LogDebug(
                "activated command={} arguments={}", uri.Host(), protocolArguments.size() - 1);
            try
            {
                arguments = tailgate::cli::Arguments::Parse(protocolArguments);
            }
            catch (const tailgate::cli::ArgumentError& error)
            {
                m_logger.LogWarning("invalid protocol arguments: {}", error.what());
            }
        }
        if (arguments)
        {
            Controller().SetArguments(*arguments);
        }
        View().Show();
    }

private:
    void EnsureResources()
    {
        if (!m_resources)
        {
            m_logger.LogDebug("loading application resources");
            m_resources =
                tailgate::uwp::GetDI().create<std::shared_ptr<tailgate::uwp::AppResources>>();
        }
    }

    tailgate::uwp::MainWindowController& Controller()
    {
        if (!m_controller)
        {
            m_logger.LogDebug("resolving MainWindowController");
            m_controller = tailgate::uwp::GetDI()
                               .create<std::shared_ptr<tailgate::uwp::MainWindowController>>();
        }
        return *m_controller;
    }

    tailgate::uwp::MainWindowView& View()
    {
        if (!m_view)
        {
            m_logger.LogDebug("resolving MainWindowView");
            m_view =
                tailgate::uwp::GetDI().create<std::unique_ptr<tailgate::uwp::MainWindowView>>();
        }
        return *m_view;
    }

    std::shared_ptr<tailgate::uwp::MainWindowController> m_controller;
    std::shared_ptr<tailgate::uwp::AppResources> m_resources;
    std::unique_ptr<tailgate::uwp::MainWindowView> m_view;
    tailgate::base::Logger m_logger{"uwp-app"};
};

} // namespace winrt::Tailgate::implementation

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    winrt::init_apartment();
    tailgate::uwp::xaml::Application::Start(
        [](auto&&)
        {
            winrt::make<winrt::Tailgate::implementation::App>();
        });
    return 0;
}
