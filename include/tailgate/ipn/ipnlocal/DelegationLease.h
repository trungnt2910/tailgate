#pragma once

#include <tailgate/base/TimeProvider.h>
#include <tailgate/hosted/Delegation.h>
#include <tailgate/ipn/ipnlocal/DerpConnections.h>

namespace tailgate::ipn::ipnlocal
{

// One authenticated relay session's ownership transaction. Expiry releases sockets;
// it never automatically reacquires a node key that may now belong to the client.
class DelegationLease final
{
public:
    DelegationLease(DerpConnections& derps, base::TimeProvider& time);
    void ApplyMap(std::uint64_t revision);
    void Accept(hosted::DelegationRequest request);
    void Poll();
    [[nodiscard]] std::vector<hosted::Frame> TakeOutput();

private:
    void Reply(hosted::DelegationStatus status,
               hosted::DelegationFailure failure = hosted::DelegationFailure::None);
    void Fail(const hosted::DelegationRequest& request, hosted::DelegationFailure failure);
    void Enable(bool enabled);
    [[nodiscard]] bool Ready() const;
    static constexpr auto LeaseDuration = std::chrono::seconds(20);
    static constexpr std::size_t MaximumReplies = 64;
    DerpConnections& m_derps;
    base::TimeProvider& m_time;
    std::uint64_t m_revision = 0;
    std::optional<hosted::DelegationRequest> m_request;
    std::optional<hosted::DelegationReply> m_reply;
    std::optional<base::TimeProvider::TimePoint> m_deadline;
    std::vector<hosted::Frame> m_output;
    bool m_changedOwnership = false;
};

} // namespace tailgate::ipn::ipnlocal
