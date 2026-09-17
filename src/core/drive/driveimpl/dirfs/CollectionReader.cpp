#include "CollectionReader.h"

#include <algorithm>
#include <utility>

#include <tailgate/drive/driveimpl/compositedav/XmlRewriter.h>

#include "drive/driveimpl/Catalog.h"

namespace tailgate::drive::driveimpl::dirfs
{

CollectionReader::CollectionReader(std::shared_ptr<const Catalog> catalog,
                                   compositedav::Path root,
                                   compositedav::PropfindQuery query,
                                   std::string modified,
                                   CollectionDepth depth)
    : m_catalog(std::move(catalog)),
      m_root(std::move(root)),
      m_query(std::move(query)),
      m_modified(std::move(modified)),
      m_depth(depth)
{
    if (!m_catalog)
    {
        throw compositedav::XmlError(compositedav::XmlErrorKind::InvalidState);
    }
}

bool CollectionReader::Finished() const noexcept
{
    return !m_failed && m_stage == Stage::Complete && m_offset == m_pending.size();
}

std::string CollectionReader::Read(std::size_t maximumBytes)
{
    if (m_failed || maximumBytes == 0)
    {
        throw compositedav::XmlError(compositedav::XmlErrorKind::InvalidState);
    }
    if (Finished())
    {
        return {};
    }
    try
    {
        if (m_offset == m_pending.size())
        {
            m_pending.clear();
            m_offset = 0;
            Generate();
            if (m_pending.size() > MaximumResponseBytes - m_generated)
            {
                throw compositedav::XmlError(compositedav::XmlErrorKind::Limit);
            }
            m_generated += m_pending.size();
        }
        const auto count = std::min(maximumBytes, m_pending.size() - m_offset);
        auto result = m_pending.substr(m_offset, count);
        m_offset += count;
        return result;
    }
    catch (...)
    {
        // Once output has started, failure must remain observable as truncation, not EOF.
        m_failed = true;
        throw;
    }
}

void CollectionReader::Collection(const compositedav::Path& path)
{
    const auto name = path.Segments().empty() ? "" : path.Segments().back();
    m_pending = compositedav::CollectionResponse(path.Encode(), name, m_modified, m_query);
}

void CollectionReader::Generate()
{
    switch (m_stage)
    {
    case Stage::Opening:
        m_pending = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><D:multistatus xmlns:D=\"DAV:\">";
        m_stage = Stage::Root;
        break;
    case Stage::Root:
        Collection(compositedav::Path::FromSegments(m_root.Segments(), true));
        m_stage = Stage::Closing;
        if (m_depth != CollectionDepth::Self)
        {
            if (m_root.Segments().empty())
            {
                m_stage = Stage::Domain;
            }
            else if (m_root.Segments().size() == 1 && !m_catalog->Remotes.empty())
            {
                m_stage = Stage::Peers;
            }
        }
        break;
    case Stage::Domain:
        Collection(compositedav::Path::FromSegments({m_catalog->Domain}, true));
        m_stage = m_depth == CollectionDepth::Recursive && !m_catalog->Remotes.empty()
                      ? Stage::Peers
                      : Stage::Closing;
        break;
    case Stage::Peers:
        Collection(compositedav::Path::FromSegments(
            {m_catalog->Domain, m_catalog->Remotes[m_peer].Name}, true));
        if (++m_peer == m_catalog->Remotes.size())
        {
            m_stage = Stage::Closing;
        }
        break;
    case Stage::Closing:
        m_pending = "</D:multistatus>";
        m_stage = Stage::Complete;
        break;
    case Stage::Complete:
        break;
    }
}

} // namespace tailgate::drive::driveimpl::dirfs
