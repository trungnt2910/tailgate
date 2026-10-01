#include "ModeRequests.h"

#include <format>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.h>

#include <tailgate/hosted/RelayEndpoint.h>

#include "common/Settings.h"

namespace tailgate::uwp::bg
{

ModeRequests::ModeRequests(service::ModeService& service,
                           tailgate::ipn::ipnlocal::SwitchingNode& node,
                           tailgate::hosted::ConnectionOptions options)
    : m_service(service), m_node(node), m_options(std::move(options))
{
}

void ModeRequests::Poll()
{
    using tailgate::ipn::ipnlocal::NodeMode;
    auto result = app_service::Status::Ok;
    if (const auto request = m_service.GetState().Request)
    {
        m_service.AcknowledgeRequest();
        try
        {
            auto relay = m_options;
            if (!request->RelayUrl.empty())
            {
                const auto endpoint = tailgate::hosted::RelayEndpoint::Parse(request->RelayUrl);
                relay.Socket.ConnectAddress = endpoint.Host;
                relay.Socket.TlsServerName = endpoint.Host;
                relay.Socket.Service = endpoint.Port;
                relay.HttpHost = std::format("{}:{}", endpoint.Host, endpoint.Port);
            }
            const auto desired = request->RelayUrl.empty() ? NodeMode::Native : NodeMode::Hosted;
            const auto currentRelay = Settings::GetString(L"TailgateServer");
            if (Settings::GetString(L"NetworkPolicyRestartRequired") == L"true" ||
                (desired == NodeMode::Hosted && m_node.Transition().Effective == NodeMode::Hosted &&
                 currentRelay != winrt::to_hstring(request->RelayUrl)))
            {
                result = app_service::Status::ReconnectRequired;
            }
            else if (m_node.RequestMode(desired, std::move(relay)))
            {
                Settings::SetString(L"TailgateServer", winrt::to_hstring(request->RelayUrl));
            }
            else
            {
                result = app_service::Status::Busy;
            }
        }
        catch (const std::invalid_argument&)
        {
            result = app_service::Status::InvalidRelay;
        }
    }
    const auto status = m_node.Transition();
    m_service.Publish(status, result);
    if (!m_published || *m_published != status)
    {
        m_published = status;
        winrt::Windows::Storage::ApplicationDataCompositeValue value;
        value.Insert(L"Desired", winrt::box_value(static_cast<std::uint32_t>(status.Desired)));
        value.Insert(L"Effective", winrt::box_value(static_cast<std::uint32_t>(status.Effective)));
        value.Insert(L"Phase", winrt::box_value(static_cast<std::uint32_t>(status.Phase)));
        value.Insert(L"Failure", winrt::box_value(static_cast<std::uint32_t>(status.Failure)));
        Settings::Set(L"ModeState", value);
        winrt::Windows::Storage::ApplicationData::Current().SignalDataChanged();
    }
}

void ModeRequests::ChangeNetwork(const std::string& networkInterface)
{
    m_options.Socket.NetworkInterface = networkInterface;
}

} // namespace tailgate::uwp::bg
