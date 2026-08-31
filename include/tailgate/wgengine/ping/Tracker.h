#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/disco/Disco.h>
#include <tailgate/net/packet/Tsmp.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::wgengine::ping
{

enum class Mode
{
    Disco,
    Tsmp,
};

enum class StartStatus
{
    Ready,
    DuplicateRequest,
    NoMatchingPeer,
    NoNodeKey,
    NoDiscoKey,
    InvalidAddress,
};

struct Request
{
    std::uint64_t Id = 0;
    std::string Target;
    Mode PingMode = Mode::Disco;
    std::chrono::steady_clock::duration Timeout = std::chrono::seconds(10);
    std::string Relay;
};

struct Probe
{
    std::uint64_t RequestId = 0;
    tailgate::crypto::Bytes32 Peer{};
    std::vector<std::uint8_t> Payload;
    bool Disco = false;
};

struct StartResult
{
    StartStatus Status = StartStatus::NoMatchingPeer;
    std::optional<Probe> Outbound;
};

struct Result
{
    std::uint64_t RequestId = 0;
    bool Responded = false;
    std::chrono::steady_clock::duration Latency{};
    std::string PeerName;
    std::string PeerAddress;
    std::string Relay;
    std::uint16_t PeerApiPort = 0;
};

class Tracker
{
public:
    using TimePoint = std::chrono::steady_clock::time_point;

    virtual ~Tracker();

    [[nodiscard]] virtual StartResult Start(const Request& request,
                                            const tailgate::types::netmap::NetworkConfig& network,
                                            tailgate::disco::Disco& disco,
                                            TimePoint now) = 0;
    [[nodiscard]] virtual std::optional<Result>
    CompleteDisco(const tailgate::crypto::Bytes32& peer,
                  const tailgate::disco::Disco::TransactionId& transaction,
                  std::uint16_t peerApiPort,
                  TimePoint now) = 0;
    [[nodiscard]] virtual std::optional<Result>
    CompleteTsmp(const tailgate::net::packet::TsmpToken& token,
                 std::uint16_t peerApiPort,
                 TimePoint now) = 0;
    [[nodiscard]] virtual std::vector<Result> Expire(TimePoint now) = 0;
    virtual void Reset() noexcept = 0;

protected:
    Tracker() = default;
};

} // namespace tailgate::wgengine::ping
