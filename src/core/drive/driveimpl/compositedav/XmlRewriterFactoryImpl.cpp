#include "XmlRewriterFactoryImpl.h"

#include <algorithm>
#include <array>
#include <exception>
#include <memory>
#include <new>

#include <expat.h>

#include "XmlRewriterImpl.h"

namespace tailgate::drive::driveimpl::compositedav
{

XmlRewriterFactoryImpl::XmlRewriterFactoryImpl(crypto::Random& random) noexcept : m_random(random)
{
}

std::unique_ptr<XmlRewriter> XmlRewriterFactoryImpl::Create(const PathMapping& mapping)
{
    std::array<std::uint8_t, 16> salt{};
    m_random.Fill(salt);
    return std::make_unique<XmlRewriterImpl>(mapping, salt);
}

namespace
{

class QueryParser final
{
public:
    explicit QueryParser(const std::array<std::uint8_t, 16>& salt, bool patch = false)
        : m_parser(XML_ParserCreateNS(nullptr, '\x1f'), XML_ParserFree), m_patch(patch)
    {
        if (!m_parser)
        {
            throw std::bad_alloc();
        }
        (void)XML_SetHashSalt16Bytes(m_parser.get(), salt.data());
        XML_SetUserData(m_parser.get(), this);
        XML_SetElementHandler(m_parser.get(), Start, End);
        XML_SetCharacterDataHandler(m_parser.get(), Text);
        XML_SetCommentHandler(m_parser.get(), Comment);
        XML_SetProcessingInstructionHandler(m_parser.get(), ProcessingInstruction);
        XML_SetStartDoctypeDeclHandler(m_parser.get(), Doctype);
    }

    PropfindQuery Parse(std::span<const std::uint8_t> input)
    {
        constexpr std::size_t MaximumQueryBytes = 64U * 1024U;
        if (input.size() > MaximumQueryBytes)
        {
            throw XmlError(XmlErrorKind::Limit);
        }
        const auto status = XML_Parse(m_parser.get(),
                                      reinterpret_cast<const char*>(input.data()),
                                      static_cast<int>(input.size()),
                                      XML_TRUE);
        if (m_error)
        {
            std::rethrow_exception(m_error);
        }
        if (status != XML_STATUS_OK || !m_selected ||
            (m_include && m_query.Selection != PropertySelection::All))
        {
            throw XmlError(XmlErrorKind::Malformed);
        }
        return std::move(m_query);
    }

private:
    template <class Action>
    void Guard(Action action) noexcept
    {
        if (m_error)
        {
            return;
        }
        try
        {
            action();
        }
        catch (...)
        {
            m_error = std::current_exception();
            (void)XML_StopParser(m_parser.get(), XML_FALSE);
        }
    }

    void AddProperty(std::string_view name)
    {
        // Namespace expansion can turn a short XML query into many large property names.
        // Bound both the expanded work and duplicate lookup cost, not only input bytes.
        constexpr std::size_t MaximumProperties = 256;
        constexpr std::size_t MaximumPropertyBytes = 64U * 1024U;
        if (m_propertyCount == MaximumProperties ||
            name.size() > MaximumPropertyBytes - m_propertyBytes)
        {
            throw XmlError(XmlErrorKind::Limit);
        }
        ++m_propertyCount;
        m_propertyBytes += name.size();
        ++m_groupProperties;
        const auto separator = name.find('\x1f');
        PropertyName property;
        property.Namespace =
            separator == std::string_view::npos ? "" : std::string(name.substr(0, separator));
        property.LocalName =
            std::string(name.substr(separator == std::string_view::npos ? 0 : separator + 1));
        if (m_patch || std::ranges::find(m_query.Properties, property) == m_query.Properties.end())
        {
            m_query.Properties.push_back(std::move(property));
        }
    }

    void PatchElement(std::string_view name)
    {
        switch (m_elements.size())
        {
        case 0:
            if (name != "DAV:\x1fpropertyupdate")
            {
                throw XmlError(XmlErrorKind::Malformed);
            }
            m_selected = true;
            break;
        case 1:
            if (name != "DAV:\x1fset" && name != "DAV:\x1fremove")
            {
                throw XmlError(XmlErrorKind::Malformed);
            }
            m_remove = name == "DAV:\x1fremove";
            break;
        case 2:
            if (name != "DAV:\x1fprop")
            {
                throw XmlError(XmlErrorKind::Malformed);
            }
            m_groupProperties = 0;
            break;
        case 3:
            AddProperty(name);
            break;
        default:
            if (m_remove)
            {
                throw XmlError(XmlErrorKind::Malformed);
            }
            break;
        }
    }

    void Element(std::string_view name)
    {
        constexpr std::size_t MaximumDepth = 64;
        if (m_elements.size() >= MaximumDepth)
        {
            throw XmlError(XmlErrorKind::Limit);
        }
        if (m_patch)
        {
            PatchElement(name);
        }
        else if (m_elements.empty())
        {
            if (name != "DAV:\x1fpropfind")
            {
                throw XmlError(XmlErrorKind::Malformed);
            }
        }
        else if (m_elements.size() == 1)
        {
            if (name == "DAV:\x1finclude")
            {
                m_include = true;
                m_groupProperties = 0;
            }
            else if (name == "DAV:\x1fprop" || name == "DAV:\x1fpropname" ||
                     name == "DAV:\x1f"
                             "allprop")
            {
                const auto selection = name == "DAV:\x1fprop"       ? PropertySelection::Selected
                                       : name == "DAV:\x1fpropname" ? PropertySelection::Names
                                                                    : PropertySelection::All;
                if (m_selected && m_query.Selection != selection)
                {
                    throw XmlError(XmlErrorKind::Malformed);
                }
                m_query.Selection = selection;
                m_groupProperties = 0;
                m_selected = true;
            }
        }
        else if (m_elements.size() == 2 &&
                 (m_elements.back() == "DAV:\x1fprop" || m_elements.back() == "DAV:\x1finclude"))
        {
            AddProperty(name);
        }
        else if (m_elements.size() >= 3 &&
                 (m_elements[1] == "DAV:\x1fprop" || m_elements[1] == "DAV:\x1finclude"))
        {
            throw XmlError(XmlErrorKind::Malformed);
        }
        m_elements.emplace_back(name);
    }

    static void XMLCALL Start(void* context, const XML_Char* name, const XML_Char**)
    {
        auto& self = *static_cast<QueryParser*>(context);
        self.Guard(
            [&]
            {
                self.Element(name);
            });
    }

    static void XMLCALL End(void* context, const XML_Char*)
    {
        auto& self = *static_cast<QueryParser*>(context);
        self.Guard(
            [&]
            {
                const auto& name = self.m_elements.back();
                const bool propertyGroup =
                    self.m_patch ? self.m_elements.size() == 3
                                 : self.m_elements.size() == 2 &&
                                       (name == "DAV:\x1fprop" || name == "DAV:\x1finclude");
                if (propertyGroup && self.m_groupProperties == 0)
                {
                    throw XmlError(XmlErrorKind::Malformed);
                }
                self.m_elements.pop_back();
            });
    }

    static void XMLCALL Text(void* context, const XML_Char*, int length)
    {
        auto& self = *static_cast<QueryParser*>(context);
        self.Guard(
            [&]
            {
                const bool propfindValue = !self.m_patch && self.m_elements.size() >= 3 &&
                                           (self.m_elements[1] == "DAV:\x1fprop" ||
                                            self.m_elements[1] == "DAV:\x1finclude");
                if (length != 0 && (propfindValue ||
                                    (self.m_patch && self.m_remove && self.m_elements.size() >= 4)))
                {
                    throw XmlError(XmlErrorKind::Malformed);
                }
            });
    }

    static void XMLCALL
    Doctype(void* context, const XML_Char*, const XML_Char*, const XML_Char*, int)
    {
        auto& self = *static_cast<QueryParser*>(context);
        self.Guard(
            []
            {
                throw XmlError(XmlErrorKind::ForbiddenMarkup);
            });
    }

    static void XMLCALL Comment(void* context, const XML_Char*)
    {
        auto& self = *static_cast<QueryParser*>(context);
        self.Guard(
            [&]
            {
                if (self.m_patch && self.m_remove && self.m_elements.size() >= 4)
                {
                    throw XmlError(XmlErrorKind::Malformed);
                }
            });
    }

    static void XMLCALL ProcessingInstruction(void* context, const XML_Char*, const XML_Char*)
    {
        Comment(context, nullptr);
    }

    std::unique_ptr<XML_ParserStruct, decltype(&XML_ParserFree)> m_parser;
    PropfindQuery m_query;
    std::vector<std::string> m_elements;
    std::exception_ptr m_error;
    bool m_selected = false;
    bool m_include = false;
    bool m_patch = false;
    bool m_remove = false;
    std::size_t m_groupProperties = 0;
    std::size_t m_propertyCount = 0;
    std::size_t m_propertyBytes = 0;
};

} // namespace

PropfindQuery XmlRewriterFactoryImpl::ParsePropfind(std::span<const std::uint8_t> input)
{
    if (input.empty())
    {
        return {};
    }
    std::array<std::uint8_t, 16> salt{};
    m_random.Fill(salt);
    return QueryParser(salt).Parse(input);
}

std::vector<PropertyName>
XmlRewriterFactoryImpl::ParseProppatch(std::span<const std::uint8_t> input)
{
    std::array<std::uint8_t, 16> salt{};
    m_random.Fill(salt);
    return QueryParser(salt, true).Parse(input).Properties;
}

} // namespace tailgate::drive::driveimpl::compositedav
