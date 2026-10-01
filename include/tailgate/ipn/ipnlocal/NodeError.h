#pragma once

#include <exception>

namespace tailgate::ipn::ipnlocal
{

enum class NodeFailure
{
    IdentityChanged,
    MissingNetworkMap,
    FunnelEnablementRequired,
    HttpsUnavailable,
    FunnelUnavailable,
    FunnelPortDenied,
    CertificateDenied,
    ExitNodeMissing,
    ExitNodeDerpMissing,
    InvalidDerpRegion,
    DerpNotProvisioned,
    InvalidTransportOptions,
};

class NodeError final : public std::exception
{
public:
    explicit NodeError(NodeFailure reason) noexcept : m_reason(reason)
    {
    }

    [[nodiscard]] NodeFailure Reason() const noexcept
    {
        return m_reason;
    }

    [[nodiscard]] const char* what() const noexcept override;

private:
    NodeFailure m_reason;
};

} // namespace tailgate::ipn::ipnlocal
