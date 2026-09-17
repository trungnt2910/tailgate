#pragma once

#include <array>
#include <exception>
#include <memory>
#include <utility>
#include <vector>

#include <expat.h>

#include <tailgate/drive/driveimpl/compositedav/XmlRewriter.h>

namespace tailgate::drive::driveimpl::compositedav
{

class XmlRewriterImpl final : public XmlRewriter
{
public:
    XmlRewriterImpl(PathMapping mapping, const std::array<std::uint8_t, 16>& salt);
    [[nodiscard]] std::string Transform(std::span<const std::uint8_t> input, bool final) override;

private:
    static void XMLCALL StartNamespace(void* context, const XML_Char* prefix, const XML_Char* uri);
    static void XMLCALL StartElement(void* context,
                                     const XML_Char* name,
                                     const XML_Char** attributes);
    static void XMLCALL EndElement(void* context, const XML_Char* name);
    static void XMLCALL Text(void* context, const XML_Char* text, int length);
    static void XMLCALL
    Doctype(void* context, const XML_Char*, const XML_Char*, const XML_Char*, int);
    static void XMLCALL SkippedEntity(void* context, const XML_Char*, int);

    template <class Action>
    void Callback(Action action) noexcept
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
            // Expat invokes C callbacks; propagate exceptions only after XML_Parse returns.
            m_error = std::current_exception();
            (void)XML_StopParser(m_parser.get(), XML_FALSE);
        }
    }

    void Append(std::string_view text);
    void OnStart(std::string_view name, const XML_Char** attributes);
    void OnEnd(std::string_view name);
    void OnText(std::string_view text);

    std::unique_ptr<XML_ParserStruct, decltype(&XML_ParserFree)> m_parser;
    PathMapping m_mapping;
    std::vector<std::string> m_elements;
    std::vector<std::pair<std::string, std::string>> m_namespaces;
    std::string m_href;
    std::string m_output;
    std::exception_ptr m_error;
    std::size_t m_inputBytes = 0;
    bool m_capturingHref = false;
    bool m_started = false;
    bool m_finished = false;
};

} // namespace tailgate::drive::driveimpl::compositedav
