#include "FileSystem.h"

#include <algorithm>
#include <chrono>
#include <format>
#include <utility>

#include <boost/url/parse.hpp>

#include <tailgate/drive/driveimpl/compositedav/IfHeader.h>

#include "drive/driveimpl/Catalog.h"

namespace tailgate::drive::driveimpl::dirfs
{

FileSystem::FileSystem(base::WallClock& clock, compositedav::XmlRewriterFactory& xml) noexcept
    : m_clock(clock), m_xml(xml)
{
}

Response FileSystem::Serve(const net::http::MessageHead& request,
                           std::string_view body,
                           std::shared_ptr<const Catalog> catalog)
{
    if (!catalog)
    {
        throw compositedav::XmlError(compositedav::XmlErrorKind::InvalidState);
    }
    if (request.Method() == "PROPFIND")
    {
        return Propfind(request, body, std::move(catalog));
    }
    return Response{.Metadata = DirectResponse(request, body, *catalog)};
}

net::http::Response FileSystem::DirectResponse(const net::http::MessageHead& request,
                                               std::string_view body,
                                               const Catalog& catalog)
{
    const auto& method = request.Method();
    if (method == "PUT" || method == "MKCOL" || method == "DELETE" || method == "COPY" ||
        method == "MOVE" || method == "PROPPATCH")
    {
        if (const auto condition = request.SingleField("If");
            condition && !compositedav::IfHeader::Parse(*condition)
                              .AllowsUnlocked(request.SingleField("Host").value_or("")))
        {
            return net::http::Response(412, {}, {});
        }
    }
    if (method == "OPTIONS")
    {
        return net::http::Response(200,
                                   {{"Allow",
                                     "OPTIONS, LOCK, DELETE, PROPPATCH, COPY, MOVE, "
                                     "UNLOCK, PROPFIND"},
                                    {"DAV", "1, 2"},
                                    {"MS-Author-Via", "DAV"}},
                                   {});
    }
    if (method == "GET" || method == "HEAD" || method == "POST" || method == "DELETE" ||
        method == "LOCK")
    {
        return net::http::Response(405, {}, {});
    }
    if (method == "MKCOL")
    {
        // Like the official dirfs, creating an existing virtual directory is idempotent.
        return net::http::Response(
            request.SingleField("Content-Length") && !body.empty() ? 415 : 201, {}, {});
    }
    if (method == "PUT")
    {
        if (!body.empty())
        {
            return net::http::Response(405, {}, {});
        }
        const auto now = m_clock.Now();
        return net::http::Response(
            201,
            {{"ETag",
              std::format(
                  "\"{:x}0\"",
                  std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch())
                      .count())},
             {"Last-Modified",
              std::format("{:%a, %d %b %Y %T} GMT",
                          std::chrono::floor<std::chrono::seconds>(now))}},
            {});
    }
    if (method == "UNLOCK")
    {
        const auto token = request.SingleField("Lock-Token");
        return net::http::Response(
            token && token->size() >= 2 && token->front() == '<' && token->back() == '>' ? 409
                                                                                         : 400,
            {},
            {});
    }
    if (method == "COPY" || method == "MOVE")
    {
        return CopyMove(request, catalog.Domain, catalog.Remotes);
    }
    if (method == "PROPPATCH")
    {
        return Proppatch(request, body);
    }
    return net::http::Response(400, {}, {});
}

net::http::Response FileSystem::CopyMove(const net::http::MessageHead& request,
                                         const std::string& domain,
                                         std::span<const Remote> remotes)
{
    const auto destination = request.SingleField("Destination");
    if (!destination || destination->empty())
    {
        return net::http::Response(400, {}, {});
    }
    const auto uri = boost::urls::parse_uri_reference(*destination);
    if (!uri)
    {
        return net::http::Response(400, {}, {});
    }
    if (uri->has_authority() &&
        uri->encoded_authority() != request.SingleField("Host").value_or(""))
    {
        return net::http::Response(502, {}, {});
    }
    if (uri->encoded_path().empty())
    {
        return net::http::Response(502, {}, {});
    }
    const auto source = compositedav::Path::Parse(request.Target());
    const auto target = compositedav::Path::Parse(uri->encoded_path());
    if (source.Segments() == target.Segments())
    {
        return net::http::Response(403, {}, {});
    }
    const auto depth = request.SingleField("Depth");
    const bool copy = request.Method() == "COPY";
    if (depth && !depth->empty() && *depth != "infinity" && (!copy || *depth != "0"))
    {
        return net::http::Response(400, {}, {});
    }
    const auto& segments = target.Segments();
    const bool exists =
        segments.empty() ||
        (segments.front() == domain &&
         (segments.size() == 1 ||
          (segments.size() == 2 && std::ranges::any_of(remotes,
                                                       [&](const Remote& remote)
                                                       {
                                                           return remote.Name == segments.back();
                                                       }))));
    const auto overwrite = request.SingleField("Overwrite");
    if (exists && (copy ? overwrite == "F" : overwrite != "T"))
    {
        return net::http::Response(412, {}, {});
    }
    return net::http::Response(403, {}, {});
}

net::http::Response FileSystem::Proppatch(const net::http::MessageHead& request,
                                          std::string_view body)
{
    const auto properties = m_xml.ParseProppatch(
        std::span(reinterpret_cast<const std::uint8_t*>(body.data()), body.size()));
    const bool protectedProperty = std::ranges::any_of(properties,
                                                       [](const auto& property)
                                                       {
                                                           return property.IsProtected();
                                                       });
    std::string denied;
    std::string dependent;
    for (const auto& property : properties)
    {
        (protectedProperty && !property.IsProtected() ? dependent : denied) += property.Encode();
    }
    std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                      "<D:multistatus xmlns:D=\"DAV:\"><D:response><D:href>" +
                      compositedav::EscapeXml(request.Target()) + "</D:href>";
    xml += "<D:propstat><D:prop>" + denied +
           "</D:prop>"
           "<D:status>HTTP/1.1 403 Forbidden</D:status>";
    if (protectedProperty)
    {
        xml += "<D:error><D:cannot-modify-protected-property/></D:error>";
    }
    xml += "</D:propstat>";
    if (!dependent.empty())
    {
        xml += "<D:propstat><D:prop>" + dependent +
               "</D:prop>"
               "<D:status>HTTP/1.1 424 Failed Dependency</D:status></D:propstat>";
    }
    xml += "</D:response></D:multistatus>";
    return net::http::Response(
        207, {{"Content-Type", "application/xml; charset=utf-8"}}, std::move(xml));
}

Response FileSystem::Propfind(const net::http::MessageHead& request,
                              std::string_view body,
                              std::shared_ptr<const Catalog> catalog)
{
    const auto depth = request.SingleField("Depth");
    if (depth && !depth->empty() && *depth != "0" && *depth != "1" && *depth != "infinity")
    {
        return Response{.Metadata = net::http::Response(400, {}, {})};
    }
    const auto scope = !depth || depth->empty() || *depth == "infinity" ? CollectionDepth::Recursive
                       : *depth == "1"                                  ? CollectionDepth::Children
                                                                        : CollectionDepth::Self;
    auto query = m_xml.ParsePropfind(
        std::span(reinterpret_cast<const std::uint8_t*>(body.data()), body.size()));
    auto modified = std::format("{:%a, %d %b %Y %T} GMT",
                                std::chrono::floor<std::chrono::seconds>(m_clock.Now()));
    return Response{.Metadata = net::http::Response(
                        207, {{"Content-Type", "application/xml; charset=utf-8"}}, {}),
                    .Collections = std::make_unique<CollectionReader>(
                        std::move(catalog),
                        compositedav::Path::Parse(request.Target()),
                        std::move(query),
                        std::move(modified),
                        scope)};
}

} // namespace tailgate::drive::driveimpl::dirfs
