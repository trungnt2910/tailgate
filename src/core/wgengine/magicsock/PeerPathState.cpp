#include "tailgate/wgengine/magicsock/PeerPathState.h"

#include <algorithm>

namespace tailgate::wgengine::magicsock
{

bool PeerPathState::HasDirectPath() const noexcept
{
    return m_directEndpoint.has_value();
}

const std::optional<Endpoint>& PeerPathState::DirectEndpoint() const noexcept
{
    return m_directEndpoint;
}

bool PeerPathState::IsVerified(const Endpoint& endpoint) const noexcept
{
    return std::find(m_verifiedEndpoints.begin(), m_verifiedEndpoints.end(), endpoint) !=
           m_verifiedEndpoints.end();
}

bool PeerPathState::TryBeginProbe(TimePoint now) noexcept
{
    if (m_directEndpoint || (m_lastDirectProbe && now - *m_lastDirectProbe < DirectProbeInterval))
    {
        return false;
    }
    m_lastDirectProbe = now;
    return true;
}

bool PeerPathState::MarkDirect(const Endpoint& endpoint)
{
    const bool changed = m_directEndpoint != endpoint;
    m_directEndpoint = endpoint;
    m_firstUnansweredDirectSend.reset();
    RememberVerified(endpoint);
    return changed;
}

void PeerPathState::MarkDirectSend(TimePoint now) noexcept
{
    if (m_directEndpoint && !m_firstUnansweredDirectSend)
    {
        m_firstUnansweredDirectSend = now;
    }
}

void PeerPathState::MarkDirectReceive() noexcept
{
    m_firstUnansweredDirectSend.reset();
}

bool PeerPathState::ExpireDirectPath(TimePoint now) noexcept
{
    if (!m_directEndpoint || !m_firstUnansweredDirectSend ||
        now - *m_firstUnansweredDirectSend <= DirectPathTimeout)
    {
        return false;
    }
    m_directEndpoint.reset();
    m_firstUnansweredDirectSend.reset();
    return true;
}

void PeerPathState::Reset(ResetMode mode) noexcept
{
    m_directEndpoint.reset();
    m_firstUnansweredDirectSend.reset();
    if (mode == ResetMode::ForgetVerifiedEndpoints)
    {
        m_verifiedEndpoints.clear();
    }
}

void PeerPathState::RememberVerified(const Endpoint& endpoint)
{
    if (IsVerified(endpoint))
    {
        return;
    }
    if (m_verifiedEndpoints.size() == MaximumVerifiedEndpoints)
    {
        m_verifiedEndpoints.erase(m_verifiedEndpoints.begin());
    }
    m_verifiedEndpoints.push_back(endpoint);
}

} // namespace tailgate::wgengine::magicsock
