#pragma once

#include <cstddef>
#include <memory>
#include <string>

#include <tailgate/drive/driveimpl/compositedav/Path.h>
#include <tailgate/drive/driveimpl/compositedav/Propfind.h>

namespace tailgate::drive::driveimpl
{

struct Catalog;

}

namespace tailgate::drive::driveimpl::dirfs
{

enum class CollectionDepth
{
    Self,
    Children,
    Recursive,
};

// Request-scoped reader created by the DI-owned filesystem. A read generates at most one
// collection, retaining the immutable catalog snapshot while the client drains its response.
class CollectionReader final
{
public:
    CollectionReader(std::shared_ptr<const Catalog> catalog,
                     compositedav::Path root,
                     compositedav::PropfindQuery query,
                     std::string modified,
                     CollectionDepth depth);
    [[nodiscard]] std::string Read(std::size_t maximumBytes);
    [[nodiscard]] bool Finished() const noexcept;

private:
    enum class Stage
    {
        Opening,
        Root,
        Domain,
        Peers,
        Closing,
        Complete,
    };

    void Generate();
    void Collection(const compositedav::Path& path);

    static constexpr std::size_t MaximumResponseBytes = 16U * 1024U * 1024U;
    std::shared_ptr<const Catalog> m_catalog;
    compositedav::Path m_root;
    compositedav::PropfindQuery m_query;
    std::string m_modified;
    CollectionDepth m_depth;
    Stage m_stage = Stage::Opening;
    std::size_t m_peer = 0;
    std::string m_pending;
    std::size_t m_offset = 0;
    std::size_t m_generated = 0;
    bool m_failed = false;
};

} // namespace tailgate::drive::driveimpl::dirfs
