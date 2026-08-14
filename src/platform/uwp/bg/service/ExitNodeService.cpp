#include "ExitNodeService.h"

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.h>
#include <winrt/base.h>

#include <tailgate/net/packet/Ipv4.h>

#include "common/Settings.h"
#include "common/VpnConstants.h"

namespace tailgate::uwp::bg::service
{
namespace
{

namespace storage = winrt::Windows::Storage;

constexpr wchar_t PendingChangeSetting[] = L"PendingExitNodeChange";
constexpr wchar_t SequenceField[] = L"Sequence";
constexpr wchar_t AddressField[] = L"Address";
constexpr wchar_t PortField[] = L"Port";
constexpr wchar_t ExitNodeField[] = L"ExitNode";
constexpr wchar_t PreserveSelectionField[] = L"PreserveSelection";

std::string ShortExitNodeName(const tailgate::types::netmap::PeerConfig& peer)
{
    std::string name = peer.Name;
    if (!name.empty() && name.back() == '.')
    {
        name.pop_back();
    }
    const std::string shortName = name.substr(0, name.find('.'));
    return shortName.empty() ? peer.Address : shortName;
}

std::vector<std::uint8_t> BuildResponse(std::uint32_t appAddress,
                                        std::uint16_t appPort,
                                        app_service::Status status,
                                        std::uint64_t sequence,
                                        const std::string& exitNode)
{
    const std::vector<std::uint8_t> payload =
        app_service::EncodeExitNodeResponse(app_service::ExitNodeResponse{
            .Result = status,
            .Sequence = sequence,
            .ExitNode = exitNode,
        });
    return tailgate::net::packet::BuildUdpPacket(VpnConstants::Network::ServiceIpv4Address,
                                                 appAddress,
                                                 VpnConstants::AppService::Port,
                                                 appPort,
                                                 payload);
}

} // namespace

ExitNodeService::ExitNodeService(manager::DataPlaneManager& dataPlaneManager)
{
    dataPlaneManager.Register(*this);
}

void ExitNodeService::Start(SessionGeneration)
{
}

void ExitNodeService::Stop()
{
    Reset();
}

void ExitNodeService::Reset()
{
    m_pending.reset();
    m_responses.clear();
    m_responseReady = false;
}

void ExitNodeService::Encapsulate(EncapsulationContext& context)
{
    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> datagram =
        tailgate::net::packet::ParseIpv4UdpDatagram(context.Original);
    if (!datagram || datagram->Destination != VpnConstants::Network::ServiceIpv4Address ||
        datagram->DestinationPort != VpnConstants::AppService::Port)
    {
        return;
    }
    const std::optional<app_service::Message> message =
        app_service::DecodeMessage(datagram->Payload);
    if (!message || message->Type != app_service::MessageType::ExitNodeRequest)
    {
        return;
    }
    const std::optional<std::uint32_t> self =
        tailgate::net::packet::ParseIpv4(context.Config.SelfAddress);
    const std::optional<app_service::ExitNodeRequest> request =
        app_service::DecodeExitNodeRequest(*message);
    if (!self || datagram->Source != *self || datagram->SourcePort == 0 || !request)
    {
        m_logger.LogWarning("discarding invalid in-tunnel exit-node request");
        return;
    }
    context.ReconnectRequested =
        context.ReconnectRequested ||
        Handle(*datagram, *request, context.Config, context.ExitNode, m_responses) ==
            ExitNodeAction::Reconnect;
}

void ExitNodeService::Decapsulate(DecapsulationContext&)
{
}

void ExitNodeService::FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput)
{
    QueuePendingResponse(m_responses);
    for (std::vector<std::uint8_t>& response : m_responses)
    {
        localOutput.push_back(std::move(response));
    }
    m_responses.clear();
}

void ExitNodeService::LoadPending(const tailgate::types::netmap::NetworkConfig& config,
                                  std::string& exitNode)
{
    m_pending = Load();
    if (!m_pending)
    {
        return;
    }
    const std::string& requested = m_pending->RequestedExitNode;
    const std::optional<std::size_t> selected =
        requested.empty() ? std::optional<std::size_t>{}
                          : tailgate::types::netmap::FindExitNode(config.Peers, requested, true);
    if (requested.empty() || selected)
    {
        exitNode = selected ? ShortExitNodeName(config.Peers[*selected]) : std::string{};
        m_pending->Result = app_service::Status::Ok;
        return;
    }
    m_pending->Result = app_service::Status::NoMatchingExitNode;
    m_logger.LogWarning("pending exit-node change is no longer available: {}", requested);
}

void ExitNodeService::CommitPending(const std::string& exitNode)
{
    if (!m_pending)
    {
        return;
    }
    if (m_pending->Result == app_service::Status::Ok)
    {
        Settings::SetString(L"ExitNode", winrt::to_hstring(exitNode));
        if (!m_pending->PreserveSelection || !exitNode.empty())
        {
            Settings::SetString(L"ExitNodeSelection", winrt::to_hstring(exitNode));
        }
    }
    m_pending->ActiveExitNode = exitNode;
    m_responseReady = true;
}

ExitNodeAction ExitNodeService::Handle(const tailgate::net::packet::Ipv4UdpDatagram& datagram,
                                       const app_service::ExitNodeRequest& request,
                                       const tailgate::types::netmap::NetworkConfig& config,
                                       const std::string& currentExitNode,
                                       std::vector<std::vector<std::uint8_t>>& appResponses)
{
    std::string activeExitNode;
    if (!request.ExitNode.empty())
    {
        const std::optional<std::size_t> selected =
            tailgate::types::netmap::FindExitNode(config.Peers, request.ExitNode, true);
        if (!selected)
        {
            appResponses.push_back(BuildResponse(datagram.Source,
                                                 datagram.SourcePort,
                                                 app_service::Status::NoMatchingExitNode,
                                                 request.Sequence,
                                                 currentExitNode));
            m_logger.LogWarning("exit-node request rejected: no online match for {}",
                                request.ExitNode);
            return ExitNodeAction::Handled;
        }
        activeExitNode = ShortExitNodeName(config.Peers[*selected]);
    }
    Store(PendingChange{
        .Sequence = request.Sequence,
        .AppAddress = datagram.Source,
        .AppPort = datagram.SourcePort,
        .RequestedExitNode = activeExitNode,
        .ActiveExitNode = {},
        .PreserveSelection = request.PreserveSelection,
        .Result = app_service::Status::Ok,
    });
    m_logger.LogInfo("accepted exit-node change seq={} exit-node={}",
                     request.Sequence,
                     activeExitNode.empty() ? "<none>" : activeExitNode.c_str());
    return ExitNodeAction::Reconnect;
}

void ExitNodeService::QueuePendingResponse(std::vector<std::vector<std::uint8_t>>& appResponses)
{
    if (!m_responseReady || !m_pending)
    {
        return;
    }
    appResponses.push_back(BuildResponse(m_pending->AppAddress,
                                         m_pending->AppPort,
                                         m_pending->Result,
                                         m_pending->Sequence,
                                         m_pending->ActiveExitNode));
    Remove();
    m_logger.LogInfo("completed exit-node change after channel restart seq={} exit-node={}",
                     m_pending->Sequence,
                     m_pending->ActiveExitNode.empty() ? "<none>"
                                                       : m_pending->ActiveExitNode.c_str());
    m_pending.reset();
    m_responseReady = false;
}

void ExitNodeService::Store(const PendingChange& pending)
{
    storage::ApplicationDataCompositeValue value;
    value.Insert(SequenceField, winrt::box_value(pending.Sequence));
    value.Insert(AddressField, winrt::box_value(pending.AppAddress));
    value.Insert(PortField, winrt::box_value(static_cast<std::uint32_t>(pending.AppPort)));
    value.Insert(ExitNodeField, winrt::box_value(winrt::to_hstring(pending.RequestedExitNode)));
    value.Insert(PreserveSelectionField, winrt::box_value(pending.PreserveSelection));
    Settings::Set(PendingChangeSetting, value);
}

std::optional<ExitNodeService::PendingChange> ExitNodeService::Load()
{
    const auto value =
        Settings::Get(PendingChangeSetting).try_as<storage::ApplicationDataCompositeValue>();
    if (!value)
    {
        return std::nullopt;
    }
    PendingChange result;
    result.Sequence = winrt::unbox_value_or<std::uint64_t>(value.TryLookup(SequenceField), 0);
    result.AppAddress = winrt::unbox_value_or<std::uint32_t>(value.TryLookup(AddressField), 0);
    const std::uint32_t port = winrt::unbox_value_or<std::uint32_t>(value.TryLookup(PortField), 0);
    result.RequestedExitNode = winrt::to_string(
        winrt::unbox_value_or<winrt::hstring>(value.TryLookup(ExitNodeField), L""));
    result.PreserveSelection =
        winrt::unbox_value_or<bool>(value.TryLookup(PreserveSelectionField), false);
    if (result.AppAddress == 0 || port == 0 || port > std::numeric_limits<std::uint16_t>::max())
    {
        m_logger.LogWarning("discarding invalid pending exit-node change");
        Settings::Remove(PendingChangeSetting);
        return std::nullopt;
    }
    result.AppPort = static_cast<std::uint16_t>(port);
    return result;
}

void ExitNodeService::Remove()
{
    Settings::Remove(PendingChangeSetting);
}

} // namespace tailgate::uwp::bg::service
