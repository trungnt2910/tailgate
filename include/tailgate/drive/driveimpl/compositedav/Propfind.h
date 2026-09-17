#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace tailgate::drive::driveimpl::compositedav
{

enum class PropertySelection
{
    All,
    Names,
    Selected,
};

struct PropertyName
{
    std::string Namespace;
    std::string LocalName;
    [[nodiscard]] bool operator==(const PropertyName&) const noexcept = default;
    [[nodiscard]] bool IsProtected() const noexcept;
    [[nodiscard]] std::string Encode(std::string_view value = {}) const;
};

struct PropfindQuery
{
    PropertySelection Selection = PropertySelection::All;
    std::vector<PropertyName> Properties;
};

[[nodiscard]] std::string CollectionResponse(std::string href,
                                             std::string name,
                                             std::string modified,
                                             const PropfindQuery& query);

} // namespace tailgate::drive::driveimpl::compositedav
