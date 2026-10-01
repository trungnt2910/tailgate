#pragma once

#include <tailgate/base/TimeProvider.h>
#include <tailgate/hosted/Delegation.h>

namespace tailgate::ipn::ipnlocal
{

enum class NodeMode
{
    Native,
    Hosted
};
enum class TransitionPhase
{
    Idle,
    Preparing,
    AwaitingMap,
    PreparingDelegation,
    Releasing,
    Activating,
    Committing,
    Draining,
    Failed
};
enum class TransitionFailure
{
    None,
    PolicyChanged,
    PreparationFailed,
    Timeout,
    Cancelled,
    DelegationRejected,
    RollbackFailed
};
enum class TransitionActionKind
{
    PrepareNative,
    PrepareHosted,
    ActivateNative,
    ActivateHosted,
    SuspendNative,
    SelectNative,
    SelectHosted,
    RetireNative,
    RetireHosted,
    RecoverHosted,
    Delegation
};

struct TransitionStatus
{
    bool operator==(const TransitionStatus&) const = default;
    NodeMode Desired = NodeMode::Native;
    NodeMode Effective = NodeMode::Native;
    TransitionPhase Phase = TransitionPhase::Idle;
    TransitionFailure Failure = TransitionFailure::None;
    std::uint64_t Generation = 0;
    bool RollingBack = false;
};

struct TransitionAction
{
    TransitionActionKind Kind = TransitionActionKind::PrepareNative;
    std::uint64_t Generation = 0;
    std::optional<hosted::DelegationRequest> Delegation;
};

// Pure serialized transition policy, shared by both hosts. Actions operate on existing
// node/path owners; they never replace identity, packet device, host policy or services.
class TransitionCoordinator final
{
public:
    TransitionCoordinator(base::TimeProvider& time, NodeMode initial);
    [[nodiscard]] bool Begin(NodeMode desired,
                             std::uint64_t mapRevision,
                             std::vector<std::uint16_t> regions,
                             bool policyUnchanged);
    void Prepared(std::uint64_t generation, bool success);
    void MapApplied(std::uint64_t revision);
    void MapChanged(std::uint64_t revision, std::vector<std::uint16_t> regions);
    void Abort(TransitionFailure failure);
    void Reply(const hosted::DelegationReply& reply);
    void NativeReady(std::uint64_t generation);
    void RelayFailed();
    void Cancel(TransitionFailure reason = TransitionFailure::Cancelled);
    void Poll();
    [[nodiscard]] const TransitionStatus& Status() const noexcept;
    [[nodiscard]] std::vector<TransitionAction> TakeActions();
    [[nodiscard]] std::optional<base::TimeProvider::TimePoint> Deadline() const noexcept;

private:
    void Action(TransitionActionKind kind);
    void Request(hosted::DelegationAction action);
    void PrepareDelegation();
    void CommitSelection(NodeMode selected);
    void Rollback(TransitionFailure reason);
    void Finish();
    [[nodiscard]] bool Active() const noexcept;
    static constexpr auto OperationTimeout = std::chrono::seconds(15);
    static constexpr auto DrainInterval = std::chrono::milliseconds(400);
    base::TimeProvider& m_time;
    TransitionStatus m_status;
    NodeMode m_original;
    std::uint64_t m_mapRevision = 0;
    std::uint64_t m_appliedRevision = 0;
    std::uint64_t m_requestId = 0;
    std::optional<hosted::DelegationRequest> m_pending;
    std::vector<std::uint16_t> m_regions;
    std::optional<base::TimeProvider::TimePoint> m_deadline;
    std::vector<TransitionAction> m_actions;
    bool m_ownershipChanged = false;
    bool m_relayAvailable = true;
};

} // namespace tailgate::ipn::ipnlocal
