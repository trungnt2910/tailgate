#include "tailgate/drive/driveimpl/compositedav/Propfind.h"

#include <algorithm>
#include <optional>

#include <tailgate/drive/driveimpl/compositedav/XmlRewriter.h>

namespace tailgate::drive::driveimpl::compositedav
{

std::string PropertyName::Encode(std::string_view value) const
{
    const auto name = Namespace.empty() ? LocalName : "P:" + LocalName;
    const auto declaration = Namespace.empty() ? "" : " xmlns:P=\"" + EscapeXml(Namespace) + '"';
    return '<' + name + declaration + '>' + std::string(value) + "</" + name + '>';
}

bool PropertyName::IsProtected() const noexcept
{
    constexpr std::string_view Properties[] = {"resourcetype",
                                               "displayname",
                                               "getcontentlength",
                                               "getlastmodified",
                                               "creationdate",
                                               "getcontentlanguage",
                                               "getcontenttype",
                                               "getetag",
                                               "lockdiscovery",
                                               "supportedlock"};
    return Namespace == "DAV:" && std::ranges::find(Properties, LocalName) != std::end(Properties);
}

namespace
{

std::optional<std::string>
Value(const PropertyName& property, const std::string& displayName, const std::string& modified)
{
    if (property.Namespace != "DAV:")
    {
        return std::nullopt;
    }
    if (property.LocalName == "displayname")
    {
        return EscapeXml(displayName);
    }
    if (property.LocalName == "resourcetype")
    {
        return "<D:collection/>";
    }
    if (property.LocalName == "getlastmodified" || property.LocalName == "creationdate")
    {
        return modified;
    }
    if (property.LocalName == "supportedlock")
    {
        return "<D:lockentry><D:lockscope><D:exclusive/></D:lockscope>"
               "<D:locktype><D:write/></D:locktype></D:lockentry>";
    }
    return std::nullopt;
}

} // namespace

std::string CollectionResponse(std::string href,
                               std::string name,
                               std::string modified,
                               const PropfindQuery& query)
{
    auto properties = query.Properties;
    if (query.Selection != PropertySelection::Selected)
    {
        for (const auto local :
             {"displayname", "resourcetype", "getlastmodified", "creationdate", "supportedlock"})
        {
            PropertyName property{.Namespace = "DAV:", .LocalName = local};
            if (std::ranges::find(properties, property) == properties.end())
            {
                properties.push_back(std::move(property));
            }
        }
    }
    std::string found;
    std::string missing;
    for (const auto& property : properties)
    {
        const auto value = Value(property, name, modified);
        if (value)
        {
            found += property.Encode(query.Selection == PropertySelection::Names ? "" : *value);
        }
        else
        {
            missing += property.Encode();
        }
    }
    std::string result = "<D:response><D:href>" + EscapeXml(href) + "</D:href>";
    if (!found.empty() || properties.empty())
    {
        result += "<D:propstat><D:prop>" + found +
                  "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>";
    }
    if (!missing.empty())
    {
        result += "<D:propstat><D:prop>" + missing +
                  "</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>";
    }
    return result + "</D:response>";
}

} // namespace tailgate::drive::driveimpl::compositedav
