#include "FileSystemForLocalImpl.h"

#include <algorithm>

namespace tailgate::drive::driveimpl
{

FileSystemForLocalImpl::FileSystemForLocalImpl(ExchangeFactory& exchanges,
                                               PeerTransport& transport) noexcept
    : m_factory(exchanges), m_transport(transport)
{
}

void FileSystemForLocalImpl::SetNetworkConfig(const types::netmap::NetworkConfig& config)
{
    auto catalog = std::make_shared<Catalog>();
    catalog->Domain = config.Domain();
    catalog->SelfKey = config.SelfKey();
    catalog->Access = config.HasCapability("drive:access");
    catalog->Remotes = DiscoverRemotes(config);
    m_logger.LogDebug("Remote namespace refreshed: access={}, remote_count={}",
                      catalog->Access,
                      catalog->Remotes.size());
    m_transport.SetCatalog(catalog);
    std::erase_if(m_exchanges,
                  [&](const auto& exchange)
                  {
                      return !exchange->Allowed(*catalog);
                  });
    m_catalog = std::move(catalog);
    for (const auto& exchange : m_exchanges)
    {
        exchange->SetCatalog(m_catalog);
    }
}

void FileSystemForLocalImpl::HandleConn(std::unique_ptr<wgengine::netstack::Stream> stream)
{
    constexpr std::size_t MaximumConnections = 32;
    if (!m_catalog || m_exchanges.size() >= MaximumConnections)
    {
        m_logger.LogWarning("Local connection rejected: catalog_available={}, active_clients={}",
                            static_cast<bool>(m_catalog),
                            m_exchanges.size());
        stream->Abort();
        return;
    }
    m_exchanges.push_back(m_factory.Create(m_catalog, std::move(stream)));
}

bool FileSystemForLocalImpl::Poll()
{
    bool progress = m_transport.Poll();
    for (const auto& exchange : m_exchanges)
    {
        progress |= exchange->Poll();
    }
    std::erase_if(m_exchanges,
                  [](const auto& exchange)
                  {
                      return exchange->Finished();
                  });
    return progress;
}

std::optional<base::TimeProvider::TimePoint> FileSystemForLocalImpl::NextDeadline() const
{
    auto result = m_transport.NextDeadline();
    for (const auto& exchange : m_exchanges)
    {
        if (!result || exchange->Deadline() < *result)
        {
            result = exchange->Deadline();
        }
    }
    return result;
}

void FileSystemForLocalImpl::Stop() noexcept
{
    m_exchanges.clear();
    m_transport.Stop();
    m_catalog.reset();
}

} // namespace tailgate::drive::driveimpl
