#include "tailgate/ipn/ipnlocal/NodeError.h"

namespace tailgate::ipn::ipnlocal
{

const char* NodeError::what() const noexcept
{
    switch (m_reason)
    {
    case NodeFailure::IdentityChanged:
        return "the network map changed the node identity";
    case NodeFailure::MissingNetworkMap:
        return "control registration completed without a network map";
    case NodeFailure::FunnelEnablementRequired:
        return "Funnel requires enablement through control";
    case NodeFailure::HttpsUnavailable:
        return "the node does not have the HTTPS capability";
    case NodeFailure::FunnelUnavailable:
        return "the node does not have the Funnel capability";
    case NodeFailure::FunnelPortDenied:
        return "control has not authorized the Funnel port";
    case NodeFailure::CertificateDenied:
        return "control has not authorized the certificate domain";
    case NodeFailure::ExitNodeMissing:
        return "the selected exit node is unavailable";
    case NodeFailure::ExitNodeDerpMissing:
        return "the selected exit node has no usable DERP region";
    case NodeFailure::InvalidDerpRegion:
        return "the network map has no usable DERP region";
    case NodeFailure::DerpNotProvisioned:
        return "DERP connections have not been provisioned";
    case NodeFailure::InvalidTransportOptions:
        return "native UDP transport requires a readiness token";
    }
    return "node initialization failed";
}

} // namespace tailgate::ipn::ipnlocal
