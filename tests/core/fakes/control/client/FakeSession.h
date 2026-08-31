#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <tailgate/control/client/Session.h>

namespace tailgate::tests::fakes::control::client
{

struct SessionState
{
    std::deque<tailgate::types::netmap::NetworkConfig> NetworkMaps;
    tailgate::control::client::RegistrationResult Registration;
    std::vector<std::string> Operations;
    tailgate::crypto::Bytes32 NodePublicKey{};
    tailgate::crypto::Bytes32 DiscoPrivateKey{};
    std::size_t PollCalls{};
    std::function<void()> BeforeRegister;
    std::function<void(bool)> NonBlockingChanged;
    bool NonBlocking{};
    bool ReadNeedsWrite{};
    bool PendingOutput{};
    bool WriteInterest{};
    bool Closed{};
};

class FakeSession final : public tailgate::control::client::Session
{
public:
    explicit FakeSession(std::shared_ptr<SessionState> state) : m_state(std::move(state))
    {
    }

    tailgate::control::client::RegistrationResult
    RegisterUntilAuthorized(const std::string&,
                            const tailgate::control::client::RegistrationOptions&) override
    {
        if (m_state->BeforeRegister)
        {
            m_state->BeforeRegister();
        }
        m_state->Operations.emplace_back("register");
        return m_state->Registration;
    }

    tailgate::types::netmap::NetworkConfig RequestNetworkMap() override
    {
        m_state->Operations.emplace_back("request-network-map");
        return {};
    }

    tailgate::control::client::FeatureEnablement QueryFeature(const std::string&) override
    {
        return {};
    }

    void SetDnsTxt(const std::string&, const std::string&) override
    {
    }

    void UpdateHostInfo(int) override
    {
        m_state->Operations.emplace_back("update-host-info");
    }

    void SetDiscoPrivateKey(const tailgate::crypto::Bytes32& privateKey) override
    {
        m_state->DiscoPrivateKey = privateKey;
    }

    void SetEndpoints(std::vector<tailgate::control::client::MapEndpoint>) override
    {
    }

    void SetPreferredDerp(int) override
    {
        m_state->Operations.emplace_back("set-preferred-derp");
    }

    std::optional<tailgate::types::netmap::NetworkConfig> PollNetworkMap() override
    {
        ++m_state->PollCalls;
        if (m_state->NetworkMaps.empty())
        {
            return std::nullopt;
        }
        tailgate::types::netmap::NetworkConfig result = std::move(m_state->NetworkMaps.front());
        m_state->NetworkMaps.pop_front();
        return result;
    }

    tailgate::types::netmap::NetworkConfig WaitForNetworkMap() override
    {
        return {};
    }

    void SetReadTimeout(std::optional<std::chrono::seconds>) override
    {
    }

    void SetWriteInterest(bool enabled) override
    {
        m_state->WriteInterest = enabled;
    }

    void SetNonBlocking(bool enabled) override
    {
        if (m_state->NonBlockingChanged)
        {
            m_state->NonBlockingChanged(enabled);
        }
        m_state->Operations.emplace_back(enabled ? "enable-nonblocking" : "disable-nonblocking");
        m_state->NonBlocking = enabled;
    }

    bool ReadNeedsWrite() const override
    {
        return m_state->ReadNeedsWrite;
    }

    bool HasPendingOutput() const override
    {
        return m_state->PendingOutput;
    }

    void Close() noexcept override
    {
        m_state->Closed = true;
    }

    void Logout() override
    {
    }

    const tailgate::crypto::Bytes32& NodePublicKey() const override
    {
        return m_state->NodePublicKey;
    }

    const tailgate::crypto::Bytes32& DiscoPrivateKey() const override
    {
        return m_state->DiscoPrivateKey;
    }

private:
    std::shared_ptr<SessionState> m_state;
};

class FakeSessionFactory final : public tailgate::control::client::SessionFactory
{
public:
    explicit FakeSessionFactory(std::shared_ptr<SessionState> state) : m_state(std::move(state))
    {
    }

    std::unique_ptr<tailgate::control::client::Session>
    CreateSession(tailgate::control::client::SessionOptions,
                  tailgate::types::nettype::TcpSocketFactory&) override
    {
        return std::make_unique<FakeSession>(m_state);
    }

private:
    std::shared_ptr<SessionState> m_state;
};

} // namespace tailgate::tests::fakes::control::client
