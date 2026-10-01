#include "tailgate/ipn/ipnlocal/TransitionCoordinator.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace tailgate::ipn::ipnlocal
{

TransitionCoordinator::TransitionCoordinator(base::TimeProvider& time, NodeMode initial)
    : m_time(time), m_original(initial)
{
    m_status.Desired = m_status.Effective = initial;
}

bool TransitionCoordinator::Active() const noexcept
{
    return m_status.Phase != TransitionPhase::Idle && m_status.Phase != TransitionPhase::Failed;
}

bool TransitionCoordinator::Begin(NodeMode desired,
                                  std::uint64_t mapRevision,
                                  std::vector<std::uint16_t> regions,
                                  bool policyUnchanged)
{
    if (Active())
    {
        return false;
    }
    if (mapRevision == 0 || regions.empty() || std::ranges::find(regions, 0) != regions.end())
    {
        throw std::invalid_argument("transition requires a map revision and DERP regions");
    }
    m_status.Desired = desired;
    m_status.Failure = TransitionFailure::None;
    m_status.RollingBack = false;
    ++m_status.Generation;
    if (!policyUnchanged)
    {
        m_status.Phase = TransitionPhase::Failed;
        m_status.Failure = TransitionFailure::PolicyChanged;
        return false;
    }
    if (desired == m_status.Effective)
    {
        m_status.Phase = TransitionPhase::Idle;
        return true;
    }
    m_original = m_status.Effective;
    m_mapRevision = mapRevision;
    m_appliedRevision = 0;
    std::ranges::sort(regions);
    regions.erase(std::unique(regions.begin(), regions.end()), regions.end());
    m_regions = std::move(regions);
    m_ownershipChanged = false;
    m_relayAvailable = true;
    m_pending.reset();
    m_status.Phase = TransitionPhase::Preparing;
    m_deadline = m_time.Now() + OperationTimeout;
    Action(desired == NodeMode::Native ? TransitionActionKind::PrepareNative
                                       : TransitionActionKind::PrepareHosted);
    return true;
}

void TransitionCoordinator::Action(TransitionActionKind kind)
{
    m_actions.push_back({.Kind = kind, .Generation = m_status.Generation, .Delegation = {}});
}

void TransitionCoordinator::Request(hosted::DelegationAction action)
{
    m_pending = hosted::DelegationRequest{.Generation = m_status.Generation,
                                          .RequestId = ++m_requestId,
                                          .MapRevision = m_mapRevision,
                                          .Action = action,
                                          .Regions = m_regions};
    m_actions.push_back({.Kind = TransitionActionKind::Delegation,
                         .Generation = m_status.Generation,
                         .Delegation = m_pending});
    m_deadline = m_time.Now() + OperationTimeout;
}

void TransitionCoordinator::PrepareDelegation()
{
    m_status.Phase = TransitionPhase::PreparingDelegation;
    Request(hosted::DelegationAction::Prepare);
}

void TransitionCoordinator::Prepared(std::uint64_t generation, bool success)
{
    if (generation != m_status.Generation || m_status.Phase != TransitionPhase::Preparing)
    {
        return;
    }
    if (!success)
    {
        Rollback(TransitionFailure::PreparationFailed);
        return;
    }
    if (m_status.Desired == NodeMode::Native && !m_relayAvailable)
    {
        m_status.Phase = TransitionPhase::Activating;
        m_ownershipChanged = true;
        Action(TransitionActionKind::ActivateNative);
        m_deadline = m_time.Now() + OperationTimeout;
        return;
    }
    if (m_status.Desired == NodeMode::Hosted)
    {
        Action(TransitionActionKind::SuspendNative);
        m_ownershipChanged = true;
        Action(TransitionActionKind::ActivateHosted);
    }
    m_status.Phase = TransitionPhase::AwaitingMap;
    m_deadline = m_time.Now() + OperationTimeout;
    if (m_appliedRevision == m_mapRevision)
    {
        PrepareDelegation();
    }
}

void TransitionCoordinator::MapApplied(std::uint64_t revision)
{
    if (!Active())
    {
        return;
    }
    m_appliedRevision = revision;
    if (revision != m_mapRevision)
    {
        return;
    }
    if (m_status.Phase == TransitionPhase::AwaitingMap)
    {
        PrepareDelegation();
    }
}

void TransitionCoordinator::MapChanged(std::uint64_t revision, std::vector<std::uint16_t> regions)
{
    if (!Active())
    {
        return;
    }
    m_mapRevision = revision;
    std::ranges::sort(regions);
    regions.erase(std::unique(regions.begin(), regions.end()), regions.end());
    m_regions = std::move(regions);
    m_appliedRevision = 0;
    if (m_status.Phase == TransitionPhase::Preparing || m_status.Phase == TransitionPhase::Draining)
    {
        return;
    }
    // Reconcile ownership against the replacement map. Old replies cannot authorize
    // either path, including a release acknowledgment already in flight.
    ++m_status.Generation;
    m_pending.reset();
    m_actions.clear();
    Action(TransitionActionKind::SuspendNative);
    m_status.Phase = TransitionPhase::AwaitingMap;
    m_deadline = m_time.Now() + OperationTimeout;
}

void TransitionCoordinator::Abort(TransitionFailure failure)
{
    if (!Active())
    {
        return;
    }
    ++m_status.Generation;
    m_status.Phase = TransitionPhase::Failed;
    m_status.Failure = failure;
    m_status.RollingBack = false;
    m_pending.reset();
    m_actions.clear();
    m_deadline.reset();
}

void TransitionCoordinator::Reply(const hosted::DelegationReply& reply)
{
    if (!Active() || !m_pending || reply.Generation != m_status.Generation ||
        reply.RequestId != m_pending->RequestId || reply.MapRevision != m_pending->MapRevision)
    {
        return;
    }
    if (reply.Status == hosted::DelegationStatus::Failed)
    {
        Rollback(TransitionFailure::DelegationRejected);
        return;
    }
    const auto action = m_pending->Action;
    using ActionType = hosted::DelegationAction;
    using ReplyStatus = hosted::DelegationStatus;
    if (action == ActionType::Prepare && reply.Status == ReplyStatus::Prepared)
    {
        const auto target = m_status.RollingBack ? m_original : m_status.Desired;
        m_status.Phase =
            target == NodeMode::Native ? TransitionPhase::Releasing : TransitionPhase::Activating;
        Request(target == NodeMode::Native ? ActionType::Release : ActionType::Acquire);
    }
    else if (action == ActionType::Release && reply.Status == ReplyStatus::Released)
    {
        m_ownershipChanged = true;
        m_status.Phase = TransitionPhase::Activating;
        m_pending.reset();
        Action(TransitionActionKind::ActivateNative);
        m_deadline = m_time.Now() + OperationTimeout;
    }
    else if (action == ActionType::Acquire && reply.Status == ReplyStatus::Ready)
    {
        CommitSelection(NodeMode::Hosted);
    }
    else if (action == ActionType::Commit && reply.Status == ReplyStatus::Committed)
    {
        m_pending.reset();
        m_status.Phase = TransitionPhase::Draining;
        m_deadline = m_time.Now() + DrainInterval;
    }
}

void TransitionCoordinator::CommitSelection(NodeMode selected)
{
    m_status.Effective = selected;
    Action(selected == NodeMode::Native ? TransitionActionKind::SelectNative
                                        : TransitionActionKind::SelectHosted);
    if (!m_relayAvailable)
    {
        m_status.Phase = TransitionPhase::Draining;
        m_deadline = m_time.Now() + DrainInterval;
        return;
    }
    m_status.Phase = TransitionPhase::Committing;
    Request(hosted::DelegationAction::Commit);
}

void TransitionCoordinator::NativeReady(std::uint64_t generation)
{
    if (generation != m_status.Generation || m_status.Phase != TransitionPhase::Activating ||
        (m_status.RollingBack ? m_original : m_status.Desired) != NodeMode::Native)
    {
        return;
    }
    CommitSelection(NodeMode::Native);
}

void TransitionCoordinator::RelayFailed()
{
    m_relayAvailable = false;
    if (!Active())
    {
        return;
    }
    Action(TransitionActionKind::RetireHosted);
    m_pending.reset();
    if (m_status.Phase == TransitionPhase::Preparing && m_status.Desired == NodeMode::Native)
    {
        return;
    }
    if (m_status.Desired == NodeMode::Native && !m_status.RollingBack)
    {
        // A dead relay cannot acknowledge. Closing it cancels delegation authentication;
        // candidate readiness still requires an authenticated native DERP connection.
        m_ownershipChanged = true;
        m_status.Phase = TransitionPhase::Activating;
        Action(TransitionActionKind::ActivateNative);
        m_deadline = m_time.Now() + OperationTimeout;
        return;
    }
    Rollback(TransitionFailure::PreparationFailed);
}

void TransitionCoordinator::Rollback(TransitionFailure reason)
{
    if (!Active())
    {
        return;
    }
    m_actions.clear();
    m_pending.reset();
    if (m_status.RollingBack)
    {
        Action(TransitionActionKind::SuspendNative);
        Action(TransitionActionKind::RetireHosted);
        if (m_original == NodeMode::Hosted)
        {
            Action(TransitionActionKind::RecoverHosted);
        }
        else
        {
            Action(TransitionActionKind::ActivateNative);
        }
        m_status.Effective = m_original;
        m_status.Phase = TransitionPhase::Failed;
        m_status.Failure = TransitionFailure::RollbackFailed;
        m_deadline.reset();
        return;
    }
    m_status.Failure = reason;
    if (!m_ownershipChanged)
    {
        Action(m_status.Desired == NodeMode::Native ? TransitionActionKind::RetireNative
                                                    : TransitionActionKind::RetireHosted);
        m_status.Phase = TransitionPhase::Failed;
        m_deadline.reset();
        return;
    }
    ++m_status.Generation; // Invalidates outstanding worker completions and ownership replies.
    m_status.RollingBack = true;
    Action(TransitionActionKind::SuspendNative);
    if (!m_relayAvailable)
    {
        Action(TransitionActionKind::RetireHosted);
        if (m_original == NodeMode::Hosted)
        {
            Action(TransitionActionKind::RecoverHosted);
            m_status.Effective = m_original;
            m_status.Phase = TransitionPhase::Failed;
            m_deadline.reset();
        }
        else
        {
            m_status.Phase = TransitionPhase::Activating;
            Action(TransitionActionKind::ActivateNative);
            m_deadline = m_time.Now() + OperationTimeout;
        }
        return;
    }
    PrepareDelegation();
}

void TransitionCoordinator::Cancel(TransitionFailure reason)
{
    Rollback(reason);
}

void TransitionCoordinator::Finish()
{
    Action(m_status.Effective == NodeMode::Native ? TransitionActionKind::RetireHosted
                                                  : TransitionActionKind::RetireNative);
    m_status.Phase = m_status.RollingBack ? TransitionPhase::Failed : TransitionPhase::Idle;
    m_deadline.reset();
    m_pending.reset();
}

void TransitionCoordinator::Poll()
{
    if (!m_deadline || m_time.Now() < *m_deadline)
    {
        return;
    }
    if (m_status.Phase == TransitionPhase::Draining)
    {
        Finish();
    }
    else
    {
        Rollback(TransitionFailure::Timeout);
    }
}

const TransitionStatus& TransitionCoordinator::Status() const noexcept
{
    return m_status;
}

std::vector<TransitionAction> TransitionCoordinator::TakeActions()
{
    return std::exchange(m_actions, {});
}

std::optional<base::TimeProvider::TimePoint> TransitionCoordinator::Deadline() const noexcept
{
    return m_deadline;
}

} // namespace tailgate::ipn::ipnlocal
