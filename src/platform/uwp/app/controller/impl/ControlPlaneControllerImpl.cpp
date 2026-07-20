#include "app/controller/impl/ControlPlaneControllerImpl.h"

#include <chrono>
#include <exception>
#include <memory>
#include <utility>

#include <tailgate/control/ControlClient.h>
#include <tailgate/control/ControlDialer.h>
#include <tailgate/protocol/ControlHandshake.h>
#include <tailgate/protocol/Crypto.h>

#include "common/HostInfo.h"
#include "common/UwpAliases.h"
#include "common/UwpTcpStream.h"

namespace tailgate::uwp
{

namespace
{

using namespace std::chrono_literals;

constexpr std::chrono::seconds LogoutIoTimeout(30);
constexpr std::chrono::seconds PlaintextControlConnectTimeout(5);

} // namespace

const ControlPlaneState& ControlPlaneControllerImpl::GetState() const noexcept
{
    return m_state;
}

void ControlPlaneControllerImpl::Logout(std::optional<protocol::Bytes32> machineKey,
                                        std::optional<protocol::Bytes32> nodeKey)
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
ControlPlaneControllerImpl::LogoutInBackground(std::optional<protocol::Bytes32> machineKey,
                                               std::optional<protocol::Bytes32> nodeKey)
{
    winrt::apartment_context uiThread;
    std::optional<UwpError::Code> failure;
    if (machineKey && nodeKey)
    {
        co_await winrt::resume_background();
        try
        {
            tailgate::protocol::HostInfo host = BuildHostInfo();
            std::unique_ptr<tailgate::control::ControlClient> control;
            tailgate::control::ControlDialOutcome<std::unique_ptr<UwpTcpStream>> dialed =
                tailgate::control::DialControlStream(
                    []
                    {
                        return std::make_unique<UwpTcpStream>(
                            tailgate::protocol::ControlHandshake::DefaultHost,
                            tailgate::protocol::ControlHandshake::PlaintextService,
                            winrt::Windows::Networking::Sockets::SocketProtectionLevel::PlainSocket,
                            LogoutIoTimeout,
                            PlaintextControlConnectTimeout);
                    },
                    []
                    {
                        return std::make_unique<UwpTcpStream>(
                            tailgate::protocol::ControlHandshake::DefaultHost,
                            tailgate::protocol::ControlHandshake::TlsService,
                            winrt::Windows::Networking::Sockets::SocketProtectionLevel::Tls12,
                            LogoutIoTimeout);
                    },
                    [&](tailgate::IByteStream& stream)
                    {
                        control = std::make_unique<tailgate::control::ControlClient>(
                            stream, *machineKey, *nodeKey, host);
                    });
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
