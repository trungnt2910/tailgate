#pragma once

#include <tailgate/ipn/ipnlocal/SwitchingNode.h>

#include "service/ModeService.h"

namespace tailgate::uwp::bg
{

class ModeRequests final
{
public:
    ModeRequests(service::ModeService& service,
                 tailgate::ipn::ipnlocal::SwitchingNode& node,
                 tailgate::hosted::ConnectionOptions options);
    void Poll();
    void ChangeNetwork(const std::string& networkInterface);

private:
    service::ModeService& m_service;
    tailgate::ipn::ipnlocal::SwitchingNode& m_node;
    tailgate::hosted::ConnectionOptions m_options;
    std::optional<tailgate::ipn::ipnlocal::TransitionStatus> m_published;
};

} // namespace tailgate::uwp::bg
