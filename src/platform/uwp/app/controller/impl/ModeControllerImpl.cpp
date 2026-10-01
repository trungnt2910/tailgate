#include "app/controller/impl/ModeControllerImpl.h"

#include <tailgate/hosted/RelayEndpoint.h>

namespace tailgate::uwp
{

ModeControllerImpl::ModeControllerImpl(ModeRpcController& rpc,
                                       SessionController& session,
                                       SettingsController& settings)
    : m_rpc(rpc), m_session(session), m_settings(settings)
{
    m_registration = rpc.GetState().Subscribe(
        [this](const auto&, const auto&)
        {
            Receive();
        });
}

const ModeState& ModeControllerImpl::GetState() const noexcept
{
    return m_state;
}

void ModeControllerImpl::SetRelay(const winrt::hstring& relayUrl)
{
    if (m_state.Busy() || m_session.GetState().ConnectionOperationActive())
    {
        return;
    }
    if (!relayUrl.empty())
    {
        try
        {
            (void)tailgate::hosted::RelayEndpoint::Parse(winrt::to_string(relayUrl));
        }
        catch (const std::invalid_argument&)
        {
            m_state.Result(app_service::Status::InvalidRelay);
            return;
        }
    }
    m_state.RelayUrl(relayUrl);
    m_state.Result(app_service::Status::Ok);
    if (!m_session.GetState().Connected())
    {
        m_settings.SetTailgateServer(relayUrl);
        return;
    }
    m_settings.Reload();
    if (m_settings.GetState().SelfAddress().empty())
    {
        m_state.Result(app_service::Status::Timeout);
        return;
    }
    const auto previous = m_settings.GetState().TailgateServer();
    if (!previous.empty() && !relayUrl.empty() && previous != relayUrl)
    {
        // Replacing a relay server remains the existing explicit reconnect operation.
        m_session.Connect(relayUrl, L"", false, true, m_settings.GetState().ConnectionSettings());
        return;
    }
    m_state.Busy(true);
    m_rpc.Request(m_settings.GetState().SelfAddress(), relayUrl);
}

void ModeControllerImpl::Receive()
{
    const auto response = m_rpc.GetState().Response();
    if (!response)
    {
        return;
    }
    using tailgate::ipn::ipnlocal::TransitionPhase;
    const bool busy = response->Result == app_service::Status::Ok &&
                      response->Transition.Phase != TransitionPhase::Idle &&
                      response->Transition.Phase != TransitionPhase::Failed;
    m_state.Update(
        [&](auto& state)
        {
            state.Transition(response->Transition);
            state.Result(response->Result);
            state.Busy(busy);
        });
    if (!busy)
    {
        m_settings.Reload();
    }
}

} // namespace tailgate::uwp
