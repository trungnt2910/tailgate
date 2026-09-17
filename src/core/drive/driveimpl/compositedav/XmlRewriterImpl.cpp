#include "XmlRewriterImpl.h"

#include <new>

namespace tailgate::drive::driveimpl::compositedav
{

namespace
{

constexpr char NamespaceSeparator = '\x1f';
constexpr std::size_t MaximumXmlBytes = 16U * 1024U * 1024U;
constexpr std::size_t MaximumOutputChunk = 256U * 1024U;
constexpr std::size_t MaximumDepth = 64;
constexpr std::size_t MaximumAttributes = 128;
constexpr std::size_t MaximumHrefBytes = 16U * 1024U;

std::string_view ExpandedName(std::string_view name)
{
    const auto first = name.find(NamespaceSeparator);
    return first == std::string_view::npos
               ? name
               : name.substr(0, name.find(NamespaceSeparator, first + 1));
}

std::string QualifiedName(std::string_view name)
{
    const auto first = name.find(NamespaceSeparator);
    if (first == std::string_view::npos)
    {
        return std::string(name);
    }
    const auto second = name.find(NamespaceSeparator, first + 1);
    const auto local =
        name.substr(first + 1, second == std::string_view::npos ? second : second - first - 1);
    return second == std::string_view::npos
               ? std::string(local)
               : std::string(name.substr(second + 1)) + ':' + std::string(local);
}

} // namespace

XmlRewriterImpl::XmlRewriterImpl(PathMapping mapping, const std::array<std::uint8_t, 16>& salt)
    : m_parser(XML_ParserCreateNS(nullptr, NamespaceSeparator), XML_ParserFree),
      m_mapping(std::move(mapping))
{
    if (!m_parser)
    {
        throw std::bad_alloc();
    }
    if (!XML_SetHashSalt16Bytes(m_parser.get(), salt.data()))
    {
        throw XmlError(XmlErrorKind::InvalidState);
    }
    XML_SetUserData(m_parser.get(), this);
    XML_SetReturnNSTriplet(m_parser.get(), XML_TRUE);
    XML_SetNamespaceDeclHandler(m_parser.get(), StartNamespace, nullptr);
    XML_SetElementHandler(m_parser.get(), StartElement, EndElement);
    XML_SetCharacterDataHandler(m_parser.get(), Text);
    XML_SetStartDoctypeDeclHandler(m_parser.get(), Doctype);
    XML_SetSkippedEntityHandler(m_parser.get(), SkippedEntity);
    (void)XML_SetParamEntityParsing(m_parser.get(), XML_PARAM_ENTITY_PARSING_NEVER);
}

std::string XmlRewriterImpl::Transform(std::span<const std::uint8_t> input, bool final)
{
    if (m_error || m_finished)
    {
        throw XmlError(XmlErrorKind::InvalidState);
    }
    if (input.size() > MaximumInputChunk || input.size() > MaximumXmlBytes - m_inputBytes)
    {
        throw XmlError(XmlErrorKind::Limit);
    }
    m_inputBytes += input.size();
    if (!m_started)
    {
        m_started = true;
        Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    }
    const auto status = XML_Parse(m_parser.get(),
                                  reinterpret_cast<const char*>(input.data()),
                                  static_cast<int>(input.size()),
                                  final ? XML_TRUE : XML_FALSE);
    if (m_error)
    {
        std::rethrow_exception(m_error);
    }
    if (status != XML_STATUS_OK)
    {
        m_finished = true;
        throw XmlError(XmlErrorKind::Malformed);
    }
    m_finished = final;
    return std::exchange(m_output, {});
}

void XmlRewriterImpl::Append(std::string_view text)
{
    if (text.size() > MaximumOutputChunk - m_output.size())
    {
        throw XmlError(XmlErrorKind::Limit);
    }
    m_output += text;
}

void XmlRewriterImpl::OnStart(std::string_view name, const XML_Char** attributes)
{
    if (m_elements.size() >= MaximumDepth || m_capturingHref)
    {
        throw XmlError(XmlErrorKind::Limit);
    }
    const auto expanded = ExpandedName(name);
    m_capturingHref =
        expanded == "DAV:\x1fhref" && !m_elements.empty() &&
        (m_elements.back() == "DAV:\x1fresponse" || m_elements.back() == "DAV:\x1flockroot");
    m_elements.emplace_back(expanded);
    Append('<' + QualifiedName(name));
    for (const auto& [prefix, uri] : m_namespaces)
    {
        Append(prefix.empty() ? " xmlns=\"" : " xmlns:" + prefix + "=\"");
        Append(EscapeXml(uri));
        Append("\"");
    }
    m_namespaces.clear();
    for (std::size_t index = 0; attributes[index] != nullptr; index += 2)
    {
        if (index / 2 >= MaximumAttributes)
        {
            throw XmlError(XmlErrorKind::Limit);
        }
        Append(' ' + QualifiedName(attributes[index]) + "=\"");
        Append(EscapeXml(attributes[index + 1]));
        Append("\"");
    }
    Append(">");
}

void XmlRewriterImpl::OnEnd(std::string_view name)
{
    if (m_capturingHref)
    {
        const auto& parent = m_elements[m_elements.size() - 2];
        Append(EscapeXml(parent == "DAV:\x1flockroot" ? m_mapping.ToLocalLockRoot(m_href)
                                                      : m_mapping.ToLocalResource(m_href)));
        m_href.clear();
        m_capturingHref = false;
    }
    Append("</" + QualifiedName(name) + '>');
    m_elements.pop_back();
}

void XmlRewriterImpl::OnText(std::string_view text)
{
    if (m_capturingHref)
    {
        if (text.size() > MaximumHrefBytes - m_href.size())
        {
            throw XmlError(XmlErrorKind::Limit);
        }
        m_href += text;
    }
    else
    {
        Append(EscapeXml(text));
    }
}

void XMLCALL XmlRewriterImpl::StartNamespace(void* context,
                                             const XML_Char* prefix,
                                             const XML_Char* uri)
{
    auto& self = *static_cast<XmlRewriterImpl*>(context);
    self.Callback(
        [&]
        {
            constexpr std::size_t MaximumNamespaceDeclarations = 128;
            if (self.m_namespaces.size() >= MaximumNamespaceDeclarations)
            {
                throw XmlError(XmlErrorKind::Limit);
            }
            self.m_namespaces.emplace_back(prefix ? prefix : "", uri ? uri : "");
        });
}

void XMLCALL XmlRewriterImpl::StartElement(void* context,
                                           const XML_Char* name,
                                           const XML_Char** attributes)
{
    auto& self = *static_cast<XmlRewriterImpl*>(context);
    self.Callback(
        [&]
        {
            self.OnStart(name, attributes);
        });
}

void XMLCALL XmlRewriterImpl::EndElement(void* context, const XML_Char* name)
{
    auto& self = *static_cast<XmlRewriterImpl*>(context);
    self.Callback(
        [&]
        {
            self.OnEnd(name);
        });
}

void XMLCALL XmlRewriterImpl::Text(void* context, const XML_Char* text, int length)
{
    auto& self = *static_cast<XmlRewriterImpl*>(context);
    self.Callback(
        [&]
        {
            self.OnText(std::string_view(text, static_cast<std::size_t>(length)));
        });
}

void XMLCALL
XmlRewriterImpl::Doctype(void* context, const XML_Char*, const XML_Char*, const XML_Char*, int)
{
    auto& self = *static_cast<XmlRewriterImpl*>(context);
    self.Callback(
        []
        {
            throw XmlError(XmlErrorKind::ForbiddenMarkup);
        });
}

void XMLCALL XmlRewriterImpl::SkippedEntity(void* context, const XML_Char*, int)
{
    auto& self = *static_cast<XmlRewriterImpl*>(context);
    self.Callback(
        []
        {
            throw XmlError(XmlErrorKind::ForbiddenMarkup);
        });
}

} // namespace tailgate::drive::driveimpl::compositedav
