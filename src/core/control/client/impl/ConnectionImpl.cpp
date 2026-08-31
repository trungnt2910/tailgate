#include "ConnectionImpl.h"

#include <algorithm>
#include <chrono>
#include <exception>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace tailgate::control::client::impl
{

ConnectionImpl::ConnectionImpl(tailgate::control::client::SessionOptions options,
                               tailgate::control::client::SessionFactory& sessionFactory,
                               tailgate::types::nettype::TcpSocketFactory& socketFactory,
                               tailgate::base::TimeProvider& timeProvider,
                               tailgate::base::EventLoop& eventLoop)
    : m_options(std::move(options)),
      m_sessionFactory(sessionFactory),
      m_socketFactory(socketFactory),
      m_timeProvider(timeProvider),
      m_eventLoop(eventLoop),
      m_nextReconnect(m_timeProvider.Now())
{
    Connect();
}

ConnectionImpl::~ConnectionImpl()
{
    if (m_reconnectThread.joinable())
    {
        m_reconnectThread.join();
    }
    Disconnect();
}

void ConnectionImpl::Connect()
{
    m_session = m_sessionFactory.CreateSession(m_options, m_socketFactory);
    if (m_discoPrivateKey)
    {
        m_session->SetDiscoPrivateKey(*m_discoPrivateKey);
    }
    if (m_endpoints)
    {
        m_session->SetEndpoints(*m_endpoints);
    }
    if (m_preferredDerp && !m_reconnecting)
    {
        m_session->SetPreferredDerp(*m_preferredDerp);
    }
    m_lastActivity = m_timeProvider.Now();
    m_nextReconnect = tailgate::base::TimeProvider::TimePoint::max();
    m_reconnectDelay = InitialReconnectDelay;
}

void ConnectionImpl::Disconnect() noexcept
{
    if (m_session)
    {
        m_session->Close();
        m_session.reset();
    }
}

void ConnectionImpl::ScheduleReconnect() noexcept
{
    Disconnect();
    m_reconnecting = true;
    m_nextReconnect = m_timeProvider.Now() + m_reconnectDelay;
    m_reconnectDelay = std::min(m_reconnectDelay * 2, MaximumReconnectDelay);
}

void ConnectionImpl::StartReconnect()
{
    if (m_reconnectThread.joinable())
    {
        m_reconnectThread.join();
    }
    const tailgate::control::client::SessionOptions options = m_options;
    const std::optional<tailgate::crypto::Bytes32> discoPrivateKey = m_discoPrivateKey;
    const std::optional<std::vector<tailgate::control::client::MapEndpoint>> endpoints =
        m_endpoints;
    m_reconnectInProgress = true;
    m_reconnectThread = std::thread(
        [this, options, discoPrivateKey, endpoints]() mutable
        {
            ReconnectResult result;
            try
            {
                result.Session = m_sessionFactory.CreateSession(options, m_socketFactory);
                if (discoPrivateKey)
                {
                    result.Session->SetDiscoPrivateKey(*discoPrivateKey);
                }
                if (endpoints)
                {
                    result.Session->SetEndpoints(*endpoints);
                }
                tailgate::control::client::RegistrationResult registration =
                    result.Session->RegisterUntilAuthorized({}, {});
                if (registration.State != tailgate::control::client::RegistrationState::Complete ||
                    !registration.Network)
                {
                    throw std::runtime_error(
                        "Control reconnect registration did not return a network map.");
                }
                const int preferredDerp = registration.Network->DerpRegion();
                result.Session->UpdateHostInfo(preferredDerp);
                result.Session->SetPreferredDerp(preferredDerp);
                result.Network = std::move(registration.Network);
            }
            catch (...)
            {
                result.Error = std::current_exception();
                if (result.Session)
                {
                    result.Session->Close();
                    result.Session.reset();
                }
            }
            {
                const std::scoped_lock lock(m_reconnectMutex);
                m_reconnectResult = std::move(result);
            }
            m_eventLoop.Wake();
        });
}

std::optional<ConnectionImpl::ReconnectResult> ConnectionImpl::TakeReconnectResult()
{
    const std::scoped_lock lock(m_reconnectMutex);
    if (!m_reconnectResult)
    {
        return std::nullopt;
    }
    std::optional<ReconnectResult> result = std::move(m_reconnectResult);
    m_reconnectResult.reset();
    return result;
}

tailgate::control::client::Session& ConnectionImpl::ActiveSession()
{
    if (!m_session)
    {
        throw std::logic_error("The control connection is unavailable.");
    }
    return *m_session;
}

const tailgate::control::client::Session& ConnectionImpl::ActiveSession() const
{
    if (!m_session)
    {
        throw std::logic_error("The control connection is unavailable.");
    }
    return *m_session;
}

tailgate::control::client::RegistrationResult ConnectionImpl::RegisterUntilAuthorized(
    const std::string& authKey, const tailgate::control::client::RegistrationOptions& options)
{
    tailgate::control::client::RegistrationResult result =
        ActiveSession().RegisterUntilAuthorized(authKey, options);
    if (result.NetworkMapStreaming && result.Network)
    {
        m_preferredDerp = result.Network->DerpRegion();
    }
    return result;
}

tailgate::types::netmap::NetworkConfig ConnectionImpl::RequestNetworkMap()
{
    return ActiveSession().RequestNetworkMap();
}

tailgate::control::client::FeatureEnablement
ConnectionImpl::QueryFeature(const std::string& feature)
{
    return ActiveSession().QueryFeature(feature);
}

void ConnectionImpl::SetDnsTxt(const std::string& name, const std::string& value)
{
    ActiveSession().SetDnsTxt(name, value);
}

void ConnectionImpl::UpdateHostInfo(int preferredDerp)
{
    ActiveSession().UpdateHostInfo(preferredDerp);
}

void ConnectionImpl::SetDiscoPrivateKey(const tailgate::crypto::Bytes32& privateKey)
{
    m_discoPrivateKey = privateKey;
    ActiveSession().SetDiscoPrivateKey(privateKey);
}

void ConnectionImpl::SetEndpoints(std::vector<tailgate::control::client::MapEndpoint> endpoints)
{
    m_endpoints = endpoints;
    ActiveSession().SetEndpoints(std::move(endpoints));
}

void ConnectionImpl::SetPreferredDerp(int region)
{
    m_preferredDerp = region;
    ActiveSession().SetPreferredDerp(region);
}

void ConnectionImpl::StartStreaming()
{
    m_streaming = true;
    ActiveSession().SetNonBlocking(true);
}

std::vector<tailgate::types::netmap::NetworkConfig> ConnectionImpl::PollNetworkMaps()
{
    std::vector<tailgate::types::netmap::NetworkConfig> result;
    while (std::optional<tailgate::types::netmap::NetworkConfig> update =
               ActiveSession().PollNetworkMap())
    {
        result.push_back(std::move(*update));
    }
    return result;
}

void ConnectionImpl::UpdateWriteInterest()
{
    ActiveSession().SetWriteInterest(ActiveSession().ReadNeedsWrite() ||
                                     ActiveSession().HasPendingOutput());
}

tailgate::control::client::ConnectionEventResult
ConnectionImpl::ProcessEvent(const tailgate::base::Event& event)
{
    if (event.Token != m_options.ReadinessToken)
    {
        return {};
    }
    tailgate::control::client::ConnectionEventResult result{
        .Handled = true,
        .Status = tailgate::control::client::ConnectionEventStatus::Ready,
        .NetworkMaps = {},
    };
    if (!m_session ||
        tailgate::base::HasReadiness(event.Readiness, tailgate::base::EventReadiness::Error) ||
        tailgate::base::HasReadiness(event.Readiness, tailgate::base::EventReadiness::Closed))
    {
        ScheduleReconnect();
        result.Status = tailgate::control::client::ConnectionEventStatus::Disconnected;
        return result;
    }
    try
    {
        if (tailgate::base::HasReadiness(event.Readiness,
                                         tailgate::base::EventReadiness::Readable) ||
            (tailgate::base::HasReadiness(event.Readiness,
                                          tailgate::base::EventReadiness::Writable) &&
             (m_session->ReadNeedsWrite() || m_session->HasPendingOutput())))
        {
            result.NetworkMaps = PollNetworkMaps();
            m_lastActivity = m_timeProvider.Now();
        }
        UpdateWriteInterest();
    }
    catch (const std::exception& error)
    {
        m_logger.LogWarning("stream interrupted error={}", error.what());
        ScheduleReconnect();
        result.Status = tailgate::control::client::ConnectionEventStatus::Disconnected;
    }
    return result;
}

std::vector<tailgate::types::netmap::NetworkConfig> ConnectionImpl::Maintain()
{
    if (m_reconnectRequested.exchange(false))
    {
        if (!m_reconnectInProgress)
        {
            ScheduleReconnect();
            m_nextReconnect = m_timeProvider.Now();
        }
    }
    if (m_session)
    {
        if (m_streaming && m_timeProvider.Now() - m_lastActivity >= SilenceTimeout)
        {
            m_logger.LogWarning("stream received no keepalive");
            ScheduleReconnect();
        }
        return {};
    }
    if (m_timeProvider.Now() < m_nextReconnect)
    {
        return {};
    }
    if (!m_reconnectInProgress)
    {
        StartReconnect();
        return {};
    }
    std::optional<ReconnectResult> reconnect = TakeReconnectResult();
    if (!reconnect)
    {
        return {};
    }
    m_reconnectThread.join();
    m_reconnectInProgress = false;
    if (reconnect->Error)
    {
        try
        {
            std::rethrow_exception(reconnect->Error);
        }
        catch (const std::exception& error)
        {
            m_logger.LogWarning("reconnect failed retry-seconds={} error={}",
                                m_reconnectDelay.count(),
                                error.what());
        }
        ScheduleReconnect();
        return {};
    }
    m_session = std::move(reconnect->Session);
    m_session->SetNonBlocking(true);
    m_session->SetWriteInterest(m_session->ReadNeedsWrite() || m_session->HasPendingOutput());
    m_reconnecting = false;
    m_nextReconnect = tailgate::base::TimeProvider::TimePoint::max();
    m_reconnectDelay = InitialReconnectDelay;
    m_lastActivity = m_timeProvider.Now();
    if (reconnect->Network)
    {
        if (reconnect->Network->DerpRegion() != 0)
        {
            m_preferredDerp = reconnect->Network->DerpRegion();
        }
        std::vector<tailgate::types::netmap::NetworkConfig> updates;
        updates.push_back(std::move(*reconnect->Network));
        return updates;
    }
    return {};
}

void ConnectionImpl::RequestReconnect() noexcept
{
    m_reconnectRequested = true;
    m_eventLoop.Wake();
}

void ConnectionImpl::Logout()
{
    ActiveSession().Logout();
}

const tailgate::crypto::Bytes32& ConnectionImpl::NodePublicKey() const
{
    return ActiveSession().NodePublicKey();
}

const tailgate::crypto::Bytes32& ConnectionImpl::DiscoPrivateKey() const
{
    return ActiveSession().DiscoPrivateKey();
}

bool ConnectionImpl::Connected() const noexcept
{
    return m_session != nullptr;
}

ConnectionFactoryImpl::ConnectionFactoryImpl(
    tailgate::control::client::SessionFactory& sessionFactory,
    tailgate::types::nettype::TcpSocketFactory& socketFactory,
    tailgate::base::TimeProvider& timeProvider,
    tailgate::base::EventLoop& eventLoop) noexcept
    : m_sessionFactory(sessionFactory),
      m_socketFactory(socketFactory),
      m_timeProvider(timeProvider),
      m_eventLoop(eventLoop)
{
}

std::unique_ptr<tailgate::control::client::Connection>
ConnectionFactoryImpl::CreateConnection(tailgate::control::client::SessionOptions options)
{
    return std::make_unique<ConnectionImpl>(
        std::move(options), m_sessionFactory, m_socketFactory, m_timeProvider, m_eventLoop);
}

} // namespace tailgate::control::client::impl
