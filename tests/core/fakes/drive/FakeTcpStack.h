#pragma once

#include <algorithm>
#include <deque>
#include <functional>
#include <memory>
#include <string>

#include <tailgate/wgengine/netstack/Error.h>
#include <tailgate/wgengine/netstack/Stack.h>

namespace tailgate::tests::fakes
{

struct FakeTcpStreamState
{
    std::string Input;
    std::string Output;
    std::size_t ReadOffset = 0;
    std::size_t WriteLimit = 4096;
    bool WriteBlocked = false;
    bool Eof = false;
    bool Aborted = false;
    bool Closed = false;
    bool Shutdown = false;
    bool EofAfterShutdown = false;
    std::function<bool()> CanRead;
};

class FakeTcpStream final : public wgengine::netstack::Stream
{
public:
    explicit FakeTcpStream(std::shared_ptr<FakeTcpStreamState> state) : m_state(std::move(state))
    {
    }

    wgengine::netstack::StreamState State() const override
    {
        return m_state->Aborted ? wgengine::netstack::StreamState::Failed
                                : (m_state->Closed ? wgengine::netstack::StreamState::Closed
                                                   : wgengine::netstack::StreamState::Open);
    }

    std::optional<std::size_t> TryWriteSome(const std::uint8_t* data, std::size_t size) override
    {
        if (m_state->WriteBlocked)
        {
            return std::nullopt;
        }
        if (m_state->Closed || m_state->Aborted)
        {
            return 0;
        }
        const auto written = std::min(size, m_state->WriteLimit);
        m_state->Output.append(reinterpret_cast<const char*>(data), written);
        return written;
    }

    std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t maximum) override
    {
        if (m_state->CanRead && !m_state->CanRead())
        {
            return std::nullopt;
        }
        const auto count = std::min(maximum, m_state->Input.size() - m_state->ReadOffset);
        if (count != 0)
        {
            const auto start = m_state->Input.begin() + m_state->ReadOffset;
            m_state->ReadOffset += count;
            return std::vector<std::uint8_t>(start, start + count);
        }
        if (m_state->Eof || (m_state->EofAfterShutdown && m_state->Shutdown) || m_state->Aborted)
        {
            return std::vector<std::uint8_t>{};
        }
        return std::nullopt;
    }

    bool TryShutdownWrite() override
    {
        m_state->Shutdown = true;
        return true;
    }

    bool TryClose() override
    {
        m_state->Closed = true;
        return true;
    }

    void Abort() noexcept override
    {
        if (!m_state->Closed)
        {
            m_state->Aborted = true;
        }
    }

private:
    std::shared_ptr<FakeTcpStreamState> m_state;
};

class FakeTcpStack final : public wgengine::netstack::Stack
{
public:
    void Start(const wgengine::netstack::Configuration& configuration) override
    {
        Configuration = configuration;
        ++Starts;
    }

    void Stop() noexcept override
    {
        ++Stops;
        Listening.clear();
        Output.clear();
        Accepted.clear();
    }

    void Listen(const wgengine::netstack::TcpEndpoint& endpoint) override
    {
        Listening.push_back(endpoint);
    }

    void InvalidatePeerPackets() override
    {
        ++PeerInvalidations;
        std::erase_if(Output,
                      [](const auto& packet)
                      {
                          return packet.Path == wgengine::netstack::PacketPath::Peer;
                      });
    }

    std::unique_ptr<wgengine::netstack::Stream>
    Connect(const wgengine::netstack::TcpEndpoint& endpoint) override
    {
        Connected = endpoint;
        ++Connections;
        if (FailConnections)
        {
            throw wgengine::netstack::Exception(wgengine::netstack::Error::ConnectionFailed);
        }
        return std::make_unique<FakeTcpStream>(Peer);
    }

    std::unique_ptr<wgengine::netstack::Stream> TakeAccepted() override
    {
        if (Accepted.empty())
        {
            return nullptr;
        }
        auto result = std::move(Accepted.front());
        Accepted.pop_front();
        return result;
    }

    bool Input(wgengine::netstack::PacketPath path, std::span<const std::uint8_t> bytes) override
    {
        InputPackets.push_back({.Path = path, .Bytes = {bytes.begin(), bytes.end()}});
        return true;
    }

    std::vector<wgengine::netstack::OutputPacket> TakeOutput(std::size_t maximum) override
    {
        std::vector<wgengine::netstack::OutputPacket> result;
        while (!Output.empty() && result.size() < maximum)
        {
            result.push_back(std::move(Output.front()));
            Output.pop_front();
        }
        return result;
    }

    bool HasOutput(wgengine::netstack::PacketPath path) const override
    {
        return std::ranges::any_of(Output,
                                   [path](const auto& packet)
                                   {
                                       return packet.Path == path;
                                   });
    }

    void Poll() override
    {
    }

    std::optional<base::TimeProvider::TimePoint> NextDeadline() const override
    {
        return Deadline;
    }

    std::shared_ptr<FakeTcpStreamState> Peer = std::make_shared<FakeTcpStreamState>();
    std::optional<wgengine::netstack::TcpEndpoint> Connected;
    std::size_t Connections = 0;
    bool FailConnections = false;
    wgengine::netstack::Configuration Configuration;
    std::size_t Starts = 0;
    std::size_t Stops = 0;
    std::size_t PeerInvalidations = 0;
    std::vector<wgengine::netstack::TcpEndpoint> Listening;
    std::vector<wgengine::netstack::OutputPacket> InputPackets;
    std::deque<wgengine::netstack::OutputPacket> Output;
    std::deque<std::unique_ptr<wgengine::netstack::Stream>> Accepted;
    std::optional<base::TimeProvider::TimePoint> Deadline;
};

} // namespace tailgate::tests::fakes
