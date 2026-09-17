#include "tailgate/drive/driveimpl/compositedav/IfHeader.h"

#include <boost/url/parse.hpp>

namespace tailgate::drive::driveimpl::compositedav
{
namespace
{

void Whitespace(std::string_view input, std::size_t& offset)
{
    while (offset < input.size() && (input[offset] == ' ' || input[offset] == '\t'))
    {
        ++offset;
    }
}

std::string_view Angle(std::string_view input, std::size_t& offset)
{
    if (offset == input.size() || input[offset++] != '<')
    {
        throw PathError(PathErrorKind::InvalidCondition);
    }
    const auto start = offset;
    while (offset < input.size() && input[offset] != '>')
    {
        const auto character = static_cast<unsigned char>(input[offset++]);
        if (character <= ' ' || character == 127 || character == '<')
        {
            throw PathError(PathErrorKind::InvalidCondition);
        }
    }
    if (offset == input.size() || offset == start)
    {
        throw PathError(PathErrorKind::InvalidCondition);
    }
    return input.substr(start, offset++ - start);
}

void EntityTag(std::string_view input, std::size_t& offset)
{
    ++offset;
    if (input.substr(offset).starts_with("W/"))
    {
        offset += 2;
    }
    if (offset == input.size() || input[offset++] != '"')
    {
        throw PathError(PathErrorKind::InvalidCondition);
    }
    while (offset < input.size() && input[offset] != '"')
    {
        const auto character = static_cast<unsigned char>(input[offset++]);
        if (character < '!' || character == 127)
        {
            throw PathError(PathErrorKind::InvalidCondition);
        }
    }
    if (offset == input.size() || ++offset == input.size() || input[offset++] != ']')
    {
        throw PathError(PathErrorKind::InvalidCondition);
    }
}

void List(std::string_view input, std::size_t& offset)
{
    ++offset;
    unsigned conditions = 0;
    Whitespace(input, offset);
    while (offset < input.size() && input[offset] != ')')
    {
        if (input.substr(offset).starts_with("Not"))
        {
            offset += 3;
            const auto before = offset;
            Whitespace(input, offset);
            if (offset == before)
            {
                throw PathError(PathErrorKind::InvalidCondition);
            }
        }
        if (offset == input.size())
        {
            throw PathError(PathErrorKind::InvalidCondition);
        }
        if (input[offset] == '<')
        {
            // Inside a list this is an opaque state token, not a resource href.
            (void)Angle(input, offset);
        }
        else if (input[offset] == '[')
        {
            EntityTag(input, offset);
        }
        else
        {
            throw PathError(PathErrorKind::InvalidCondition);
        }
        ++conditions;
        Whitespace(input, offset);
    }
    if (conditions == 0 || offset == input.size() || input[offset++] != ')')
    {
        throw PathError(PathErrorKind::InvalidCondition);
    }
}

} // namespace

IfHeader IfHeader::Parse(std::string_view condition)
{
    IfHeader result;
    result.m_condition = condition;
    if (condition.empty())
    {
        return result;
    }
    std::size_t offset = 0;
    Whitespace(condition, offset);
    if (offset == condition.size())
    {
        throw PathError(PathErrorKind::InvalidCondition);
    }
    const bool tagged = condition[offset] == '<';
    while (offset < condition.size())
    {
        if (tagged)
        {
            const auto start = offset;
            (void)Angle(condition, offset);
            result.m_references.push_back(Reference{.Start = start, .End = offset});
        }
        Whitespace(condition, offset);
        unsigned lists = 0;
        while (offset < condition.size() && condition[offset] == '(')
        {
            List(condition, offset);
            ++lists;
            Whitespace(condition, offset);
        }
        if (lists == 0 || (!tagged && offset != condition.size()))
        {
            throw PathError(PathErrorKind::InvalidCondition);
        }
    }
    return result;
}

std::string IfHeader::Rewrite(const PathMapping& mapping) const
{
    std::string result;
    std::size_t offset = 0;
    for (const auto& reference : m_references)
    {
        result += std::string_view(m_condition).substr(offset, reference.Start - offset);
        const auto resource = std::string_view(m_condition)
                                  .substr(reference.Start + 1, reference.End - reference.Start - 2);
        result += '<' + mapping.ToPeerResource(resource) + '>';
        offset = reference.End;
    }
    result += std::string_view(m_condition).substr(offset);
    return result;
}

bool IfHeader::AllowsUnlocked(std::string_view authority) const
{
    if (m_references.empty())
    {
        return true;
    }
    for (const auto& reference : m_references)
    {
        const auto resource = std::string_view(m_condition)
                                  .substr(reference.Start + 1, reference.End - reference.Start - 2);
        const auto uri = boost::urls::parse_uri_reference(resource);
        if (uri && uri->encoded_authority() == authority)
        {
            return true;
        }
    }
    return false;
}

} // namespace tailgate::drive::driveimpl::compositedav
