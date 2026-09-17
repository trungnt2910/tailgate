#pragma once

#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>

#include <tailgate/drive/driveimpl/compositedav/Path.h>
#include <tailgate/drive/driveimpl/compositedav/Propfind.h>

namespace tailgate::drive::driveimpl::compositedav
{

enum class XmlErrorKind
{
    Malformed,
    ForbiddenMarkup,
    Limit,
    InvalidState,
};

class XmlError final : public std::exception
{
public:
    explicit XmlError(XmlErrorKind kind) noexcept;
    [[nodiscard]] XmlErrorKind Kind() const noexcept;
    [[nodiscard]] const char* what() const noexcept override;

private:
    XmlErrorKind m_kind;
};

class XmlRewriter
{
public:
    static constexpr std::size_t MaximumInputChunk = 16U * 1024U;

    virtual ~XmlRewriter();
    // Drain returned output before supplying more input. An error after partial output requires
    // terminating the HTTP exchange without its final chunk, so clients observe truncation.
    [[nodiscard]] virtual std::string Transform(std::span<const std::uint8_t> input,
                                                bool final) = 0;
};

class XmlRewriterFactory
{
public:
    virtual ~XmlRewriterFactory();
    [[nodiscard]] virtual std::unique_ptr<XmlRewriter> Create(const PathMapping& mapping) = 0;
    [[nodiscard]] virtual PropfindQuery ParsePropfind(std::span<const std::uint8_t> input) = 0;
    [[nodiscard]] virtual std::vector<PropertyName>
    ParseProppatch(std::span<const std::uint8_t> input) = 0;
};

[[nodiscard]] std::string EscapeXml(std::string_view text);

} // namespace tailgate::drive::driveimpl::compositedav
