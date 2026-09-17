#pragma once

#include <string>
#include <string_view>
#include <vector>

#include <tailgate/drive/driveimpl/compositedav/Path.h>

namespace tailgate::drive::driveimpl::compositedav
{

class IfHeader final
{
public:
    [[nodiscard]] static IfHeader Parse(std::string_view condition);
    [[nodiscard]] std::string Rewrite(const PathMapping& mapping) const;
    // Official virtual directories have a fresh, empty lock system for each request.
    [[nodiscard]] bool AllowsUnlocked(std::string_view authority) const;

private:
    struct Reference
    {
        std::size_t Start = 0;
        std::size_t End = 0;
    };

    std::string m_condition;
    std::vector<Reference> m_references;
};

} // namespace tailgate::drive::driveimpl::compositedav
