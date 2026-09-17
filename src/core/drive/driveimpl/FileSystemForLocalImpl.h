#pragma once

#include <tailgate/base/Logger.h>
#include <tailgate/drive/FileSystemForLocal.h>

#include "Exchange.h"

namespace tailgate::drive::driveimpl
{

class FileSystemForLocalImpl final : public FileSystemForLocal
{
public:
    FileSystemForLocalImpl(ExchangeFactory& exchanges, PeerTransport& transport) noexcept;
    void SetNetworkConfig(const types::netmap::NetworkConfig& config) override;
    void HandleConn(std::unique_ptr<wgengine::netstack::Stream> stream) override;
    [[nodiscard]] bool Poll() override;
    [[nodiscard]] std::optional<base::TimeProvider::TimePoint> NextDeadline() const override;
    void Stop() noexcept override;

private:
    ExchangeFactory& m_factory;
    PeerTransport& m_transport;
    std::shared_ptr<const Catalog> m_catalog;
    std::vector<std::unique_ptr<Exchange>> m_exchanges;
    base::Logger m_logger{"drive"};
};

} // namespace tailgate::drive::driveimpl
