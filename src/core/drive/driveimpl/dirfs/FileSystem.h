#pragma once

#include <span>
#include <string>
#include <string_view>

#include <tailgate/base/WallClock.h>
#include <tailgate/drive/Remote.h>
#include <tailgate/drive/driveimpl/compositedav/XmlRewriter.h>
#include <tailgate/net/http/Client.h>

#include "CollectionReader.h"

namespace tailgate::drive::driveimpl::dirfs
{

struct Response
{
    net::http::Response Metadata;
    std::unique_ptr<CollectionReader> Collections{};
};

// The local namespace contains only synthetic directories. It never opens host files.
class FileSystem final
{
public:
    FileSystem(base::WallClock& clock, compositedav::XmlRewriterFactory& xml) noexcept;
    [[nodiscard]] Response Serve(const net::http::MessageHead& request,
                                 std::string_view body,
                                 std::shared_ptr<const Catalog> catalog);

private:
    [[nodiscard]] net::http::Response DirectResponse(const net::http::MessageHead& request,
                                                     std::string_view body,
                                                     const Catalog& catalog);
    [[nodiscard]] net::http::Response Proppatch(const net::http::MessageHead& request,
                                                std::string_view body);
    [[nodiscard]] net::http::Response CopyMove(const net::http::MessageHead& request,
                                               const std::string& domain,
                                               std::span<const Remote> remotes);
    [[nodiscard]] Response Propfind(const net::http::MessageHead& request,
                                    std::string_view body,
                                    std::shared_ptr<const Catalog> catalog);

    base::WallClock& m_clock;
    compositedav::XmlRewriterFactory& m_xml;
};

} // namespace tailgate::drive::driveimpl::dirfs
