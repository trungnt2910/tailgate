#pragma once

#include <optional>
#include <vector>

#include <tailgate/wgengine/ping/Tracker.h>

namespace tailgate::wgengine::ping::impl
{

class TrackerImpl final : public Tracker
{
public:
    [[nodiscard]] StartResult Start(const Request& request,
                                    const tailgate::types::netmap::NetworkConfig& network,
                                    tailgate::disco::Disco& disco,
                                    TimePoint now) override;
    [[nodiscard]] std::optional<Result>
    CompleteDisco(const tailgate::crypto::Bytes32& peer,
                  const tailgate::disco::Disco::TransactionId& transaction,
                  std::uint16_t peerApiPort,
                  TimePoint now) override;
    [[nodiscard]] std::optional<Result> CompleteTsmp(const tailgate::net::packet::TsmpToken& token,
                                                     std::uint16_t peerApiPort,
                                                     TimePoint now) override;
    [[nodiscard]] std::vector<Result> Expire(TimePoint now) override;
    void Reset() noexcept override;

private:
    struct Pending
    {
        Request RequestState;
        tailgate::crypto::Bytes32 Peer{};
        tailgate::disco::Disco::TransactionId DiscoTransaction{};
        tailgate::net::packet::TsmpToken TsmpToken{};
        TimePoint Started{};
        std::string PeerName;
        std::string PeerAddress;
        std::string Relay;
    };

    [[nodiscard]] Result Complete(const Pending& pending,
                                  bool responded,
                                  std::uint16_t peerApiPort,
                                  TimePoint now) const;

    std::vector<Pending> m_pending;
};

} // namespace tailgate::wgengine::ping::impl
