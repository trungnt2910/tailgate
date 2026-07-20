#include "app/controller/impl/TailgateRelayControllerImpl.h"

#include <chrono>
#include <exception>
#include <format>
#include <string>
#include <string_view>
#include <utility>

#include "common/TailgateRelay.h"
#include "common/UwpAliases.h"
#include "common/UwpError.h"
#include "common/VpnConstants.h"

namespace tailgate::uwp
{

namespace
{

constexpr std::chrono::seconds TailgatePreflightTimeout{40};

winrt::hstring NormalizeTailgateServer(const winrt::hstring& value)
{
    if (value.empty())
    {
        UwpError::Throw(UwpError::Code::VpnServerRequired);
    }
    winrt::hstring normalized = value;
    if (std::wstring_view(normalized).find(L"://") == std::wstring_view::npos)
    {
        normalized = L"https://" + normalized;
    }
    try
    {
        foundation::Uri uri(normalized);
        if (uri.SchemeName() != L"https" || uri.Host().empty())
        {
            UwpError::Throw(UwpError::Code::VpnServerInvalid);
        }
        return uri.AbsoluteUri();
    }
    catch (const winrt::hresult_error& error)
    {
        if (UwpError::FromHresult(error.code()))
        {
            throw;
        }
        UwpError::Throw(UwpError::Code::VpnServerInvalid);
    }
}

} // namespace

const TailgateRelayState& TailgateRelayControllerImpl::GetState() const noexcept
{
    return m_state;
}

void TailgateRelayControllerImpl::Preflight(std::uint64_t operationId,
                                            const winrt::hstring& tailgateServer)
{
    if (m_state.Busy())
    {
        m_logger.LogDebug("superseding active relay preflight");
    }
    m_state.Update(
        [&](TailgateRelayState& state)
        {
            state.OperationId(operationId);
            state.RequestedTailgateServer(tailgateServer);
            state.TailgateServer({});
            state.Busy(true);
            state.Error(std::nullopt);
        });
    (void)PreflightInBackground(operationId, tailgateServer);
}

FireAndForget TailgateRelayControllerImpl::PreflightInBackground(std::uint64_t operationId,
                                                                 winrt::hstring tailgateServer)
{
    winrt::apartment_context uiThread;
    winrt::hstring normalizedTailgateServer;
    std::optional<UwpError::Code> failure;
    try
    {
        normalizedTailgateServer = NormalizeTailgateServer(tailgateServer);
        const foundation::Uri server(normalizedTailgateServer);
        const std::string relayHost = winrt::to_string(server.Host());
        const std::string relayService =
            server.Port() > 0 ? std::format("{}", server.Port())
                              : winrt::to_string(VpnConstants::Relay::DefaultService);
        co_await winrt::resume_background();
        TailgateRelay relay(relayHost, relayService);
        relay.Preflight(TailgatePreflightTimeout);
    }
    catch (const winrt::hresult_error& error)
    {
        failure =
            UwpError::FromHresult(error.code()).value_or(UwpError::Code::RelayConnectionFailed);
        m_logger.LogWarning(
            "preflight failed hresult={} message={}", error.code(), error.message());
    }
    catch (const std::exception& error)
    {
        failure = UwpError::Code::RelayConnectionFailed;
        m_logger.LogWarning("preflight failed: {}", error.what());
    }

    co_await uiThread;
    if (m_state.OperationId() != operationId)
    {
        co_return;
    }
    m_state.Update(
        [&](TailgateRelayState& state)
        {
            state.TailgateServer(std::move(normalizedTailgateServer));
            state.Error(failure);
            state.Busy(false);
        });
}

} // namespace tailgate::uwp
