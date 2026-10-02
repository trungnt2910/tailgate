#pragma once

#include <cstddef>

namespace tailgate::uwp::bg::manager
{

// Callers serialize access. Only one recovery may own the profile at a time.
class ProfileRecoveryState final
{
public:
    enum class Phase
    {
        Idle,
        Pending,
        Disconnecting,
        Dialing,
        Cancelled
    };

    void EnterConnect()
    {
        ++m_connects;
        if (m_phase == Phase::Pending)
        {
            m_phase = Phase::Idle;
        }
    }

    void LeaveConnect()
    {
        --m_connects;
    }

    bool Request()
    {
        if (m_phase != Phase::Idle)
        {
            return false;
        }
        m_phase = Phase::Pending;
        m_attemptTerminated = false;
        return true;
    }

    void AttemptTerminated()
    {
        m_attemptTerminated = true;
    }

    bool Claim()
    {
        if (m_phase != Phase::Pending || m_connects != 0 || !m_attemptTerminated)
        {
            return false;
        }
        m_phase = Phase::Disconnecting;
        return true;
    }

    // Windows may disconnect the failed channel before the dispatcher claims recovery.
    // That cleanup, and recovery's own disconnect, must not cancel the queued redial.
    bool Disconnecting()
    {
        if (m_phase == Phase::Pending || m_phase == Phase::Disconnecting)
        {
            return false;
        }
        const bool cancel = m_phase != Phase::Idle;
        if (cancel)
        {
            m_phase = Phase::Cancelled;
        }
        return cancel;
    }

    bool BeginDial()
    {
        if (m_phase != Phase::Disconnecting)
        {
            return false;
        }
        m_phase = Phase::Dialing;
        return true;
    }

    void Finish()
    {
        m_phase = Phase::Idle;
    }

private:
    Phase m_phase = Phase::Idle;
    std::size_t m_connects = 0;
    bool m_attemptTerminated = false;
};

} // namespace tailgate::uwp::bg::manager
