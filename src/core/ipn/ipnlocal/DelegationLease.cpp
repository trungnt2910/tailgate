#include "tailgate/ipn/ipnlocal/DelegationLease.h"

#include <algorithm>
#include <system_error>
#include <utility>

namespace tailgate::ipn::ipnlocal
{

DelegationLease::DelegationLease(DerpConnections& derps, base::TimeProvider& time)
    : m_derps(derps), m_time(time)
{
}

void DelegationLease::ApplyMap(std::uint64_t revision)
{
    m_revision = revision;
}

void DelegationLease::Fail(const hosted::DelegationRequest& request,
                           hosted::DelegationFailure failure)
{
    if (m_output.size() >= MaximumReplies)
    {
        throw std::system_error(std::make_error_code(std::errc::no_buffer_space));
    }
    m_output.push_back(
        hosted::EncodeDelegation(hosted::DelegationReply{.Generation = request.Generation,
                                                         .RequestId = request.RequestId,
                                                         .MapRevision = request.MapRevision,
                                                         .Status = hosted::DelegationStatus::Failed,
                                                         .Failure = failure}));
}

void DelegationLease::Reply(hosted::DelegationStatus status, hosted::DelegationFailure failure)
{
    if (m_output.size() >= MaximumReplies)
    {
        throw std::system_error(std::make_error_code(std::errc::no_buffer_space));
    }
    m_reply = hosted::DelegationReply{.Generation = m_request->Generation,
                                      .RequestId = m_request->RequestId,
                                      .MapRevision = m_request->MapRevision,
                                      .Status = status,
                                      .Failure = failure};
    m_output.push_back(hosted::EncodeDelegation(*m_reply));
}

void DelegationLease::Enable(bool enabled)
{
    // Ownership is node-wide, including regions introduced by subsequent maps.
    m_derps.SetEnabled(enabled);
}

bool DelegationLease::Ready() const
{
    return std::ranges::all_of(m_request->Regions,
                               [this](auto region)
                               {
                                   return m_derps.ForRegion(region).Connected();
                               });
}

void DelegationLease::Accept(hosted::DelegationRequest request)
{
    Poll();
    using Action = hosted::DelegationAction;
    using Failure = hosted::DelegationFailure;
    using Status = hosted::DelegationStatus;
    if (m_request && request == *m_request)
    {
        if (m_reply)
        {
            if (m_output.size() >= MaximumReplies)
            {
                throw std::system_error(std::make_error_code(std::errc::no_buffer_space));
            }
            m_output.push_back(hosted::EncodeDelegation(*m_reply));
        }
        return;
    }
    if (m_request && (request.Generation < m_request->Generation ||
                      (request.Generation == m_request->Generation &&
                       request.RequestId <= m_request->RequestId)))
    {
        Fail(request, Failure::StaleGeneration);
        return;
    }
    if (request.MapRevision != m_revision)
    {
        Fail(request, Failure::StaleMap);
        return;
    }
    for (auto region : request.Regions)
    {
        if (std::ranges::find(m_derps.Entries(), region, &DerpRuntime::Region) ==
            m_derps.Entries().end())
        {
            Fail(request, Failure::UnknownRegion);
            return;
        }
    }
    if (request.Action != Action::Prepare &&
        (!m_request || request.Generation != m_request->Generation ||
         request.Regions != m_request->Regions || !m_deadline))
    {
        Fail(request, Failure::InvalidState);
        return;
    }
    if ((request.Action == Action::Prepare && m_request &&
         request.Generation == m_request->Generation) ||
        ((request.Action == Action::Release || request.Action == Action::Acquire) &&
         (!m_reply || m_reply->Status != Status::Prepared)))
    {
        Fail(request, Failure::InvalidState);
        return;
    }
    if (request.Action == Action::Commit &&
        (!m_reply || (m_reply->Status != Status::Ready && m_reply->Status != Status::Released)))
    {
        Fail(request, Failure::InvalidState);
        return;
    }
    if (m_request && request.Generation > m_request->Generation && m_changedOwnership)
    {
        Enable(false);
    }
    m_request = std::move(request);
    m_reply.reset();
    m_deadline = m_time.Now() + LeaseDuration;
    switch (m_request->Action)
    {
    case Action::Prepare:
        m_changedOwnership = false;
        Reply(Status::Prepared);
        break;
    case Action::Release:
        Enable(false);
        m_changedOwnership = true;
        // SetEnabled returns only after cancellation, socket close, queue settlement.
        Reply(Status::Released);
        break;
    case Action::Acquire:
        Enable(true);
        m_changedOwnership = true;
        Poll();
        break;
    case Action::Commit:
        m_deadline.reset();
        m_changedOwnership = false;
        Reply(Status::Committed);
        break;
    }
}

void DelegationLease::Poll()
{
    if (!m_deadline)
    {
        return;
    }
    if (m_time.Now() >= *m_deadline)
    {
        if (m_changedOwnership)
        {
            Enable(false);
        }
        m_deadline.reset();
        Reply(hosted::DelegationStatus::Failed, hosted::DelegationFailure::LeaseExpired);
        return;
    }
    if (m_request->Action == hosted::DelegationAction::Acquire && !m_reply && Ready())
    {
        Reply(hosted::DelegationStatus::Ready);
    }
}

std::vector<hosted::Frame> DelegationLease::TakeOutput()
{
    return std::exchange(m_output, {});
}

} // namespace tailgate::ipn::ipnlocal
