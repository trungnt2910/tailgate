#include "app/controller/impl/PingDialogControllerImpl.h"

namespace tailgate::uwp
{

PingDialogControllerImpl::PingDialogControllerImpl(ContentDialogController& dialogController,
                                                   PingController& pingController)
    : m_dialogController(dialogController), m_pingController(pingController)
{
}

const PingDialogState& PingDialogControllerImpl::GetState() const noexcept
{
    return m_state;
}

void PingDialogControllerImpl::Show(const winrt::hstring& deviceName,
                                    const winrt::hstring& address,
                                    const winrt::hstring& selfAddress)
{
    m_pingController.Stop();
    m_state.Update(
        [&](PingDialogState& state)
        {
            state.DeviceName(deviceName);
            state.Error(PingDialogError::None);
            state.ErrorDetail({});
        });
    m_dialogController.ShowDialog(ContentDialogControllerState::Ping);

    if (!selfAddress.empty() && address == selfAddress)
    {
        m_state.Update(
            [&](PingDialogState& state)
            {
                state.Error(PingDialogError::LocalAddress);
                state.ErrorDetail(address);
            });
    }
    else if (address.empty())
    {
        m_state.Update(
            [](PingDialogState& state)
            {
                state.Error(PingDialogError::InvalidAddress);
                state.ErrorDetail({});
            });
    }
    else
    {
        m_logger.LogInfo("started device={} address={}", deviceName, address);
        m_pingController.Start(address, selfAddress);
    }
}

void PingDialogControllerImpl::Hide()
{
    m_pingController.Stop();
    m_dialogController.HideDialog(ContentDialogControllerState::Ping);
}

void PingDialogControllerImpl::OnClosed()
{
    m_pingController.Stop();
}

} // namespace tailgate::uwp
