#include "app/controller/impl/ControlPlaneControllerImpl.h"

#include <chrono>
#include <exception>
#include <memory>
#include <utility>

#include <tailgate/crypto/Crypto.h>

#include "common/TcpSocketFactory.h"

namespace tailgate::uwp
{

namespace
{

using namespace std::chrono_literals;

constexpr std::chrono::seconds LogoutIoTimeout(30);
constexpr std::chrono::seconds PlaintextControlConnectTimeout(5);

} // namespace

ControlPlaneControllerImpl::ControlPlaneControllerImpl(
    tailgate::control::client::SessionFactory& controlSessionFactory,
    TcpSocketFactory& socketFactory) noexcept
    : m_controlSessionFactory(controlSessionFactory), m_socketFactory(socketFactory)
{
}

const ControlPlaneState& ControlPlaneControllerImpl::GetState() const noexcept
{
    return m_state;
}

void ControlPlaneControllerImpl::Logout(std::optional<tailgate::crypto::Bytes32> machineKey,
                                        std::optional<tailgate::crypto::Bytes32> nodeKey)
{
    if (m_state.Busy())
    {
        m_logger.LogDebug("ignoring logout: control-plane operation is active");
        return;
    }
    m_state.Update(
        [](ControlPlaneState& state)
        {
            state.Busy(true);
            state.Error(std::nullopt);
        });
    (void)LogoutInBackground(std::move(machineKey), std::move(nodeKey));
}

FireAndForget
ControlPlaneControllerImpl::LogoutInBackground(std::optional<tailgate::crypto::Bytes32> machineKey,
                                               std::optional<tailgate::crypto::Bytes32> nodeKey)
{
    winrt::apartment_context uiThread;
    std::optional<UwpError::Code> failure;
    if (machineKey && nodeKey)
    {
        co_await winrt::resume_background();
        try
        {
            std::unique_ptr<tailgate::control::client::Session> control =
                m_controlSessionFactory.CreateSession(
                    tailgate::control::client::SessionOptions{
                        .Host = {},
                        .MachinePrivateKey = *machineKey,
                        .NodePrivateKey = *nodeKey,
                        .ExternalNodePublicKey = std::nullopt,
                        .NetworkInterface = {},
                        .ReadinessToken = {},
                        .IoTimeout = LogoutIoTimeout,
                        .PlaintextConnectTimeout = PlaintextControlConnectTimeout,
                    },
                    m_socketFactory);
            control->Logout();
            m_logger.LogInfo("node key expired with control");
        }
        catch (const winrt::hresult_error& error)
        {
            failure = UwpError::FromHresult(error.code()).value_or(UwpError::Code::Unexpected);
            m_logger.LogWarning("logout failed: {}", error.message());
        }
        catch (const std::exception& error)
        {
            failure = UwpError::Code::Unexpected;
            m_logger.LogWarning("logout failed: {}", error.what());
        }
    }

    co_await uiThread;
    m_state.Update(
        [&](ControlPlaneState& state)
        {
            state.Error(failure);
            state.Busy(false);
        });
}

} // namespace tailgate::uwp
