#pragma once

#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tailgate::net::http
{

enum class MessageKind
{
    Request,
    Response,
};

class Response;

class HeaderField
{
public:
    HeaderField(std::string name, std::string value)
        : m_name(std::move(name)), m_value(std::move(value))
    {
    }

    [[nodiscard]] const std::string& Name() const noexcept
    {
        return m_name;
    }

    void Name(std::string name)
    {
        m_name = std::move(name);
    }

    [[nodiscard]] const std::string& Value() const noexcept
    {
        return m_value;
    }

    void Value(std::string value)
    {
        m_value = std::move(value);
    }

    [[nodiscard]] bool HasName(std::string_view name) const noexcept;
    [[nodiscard]] static bool EqualText(std::string_view left, std::string_view right) noexcept;
    void ValidateTrailer() const;

private:
    std::string m_name;
    std::string m_value;
};

class MessageHead
{
public:
    [[nodiscard]] MessageKind Kind() const noexcept
    {
        return m_kind;
    }

    void Kind(MessageKind kind) noexcept
    {
        m_kind = kind;
    }

    [[nodiscard]] unsigned Version() const noexcept
    {
        return m_version;
    }

    void Version(unsigned version) noexcept
    {
        m_version = version;
    }

    [[nodiscard]] const std::string& Method() const noexcept
    {
        return m_method;
    }

    void Method(std::string method)
    {
        m_method = std::move(method);
    }

    [[nodiscard]] const std::string& Target() const noexcept
    {
        return m_target;
    }

    void Target(std::string target)
    {
        m_target = std::move(target);
    }

    [[nodiscard]] unsigned Status() const noexcept
    {
        return m_status;
    }

    void Status(unsigned status) noexcept
    {
        m_status = status;
    }

    [[nodiscard]] const std::string& Reason() const noexcept
    {
        return m_reason;
    }

    void Reason(std::string reason)
    {
        m_reason = std::move(reason);
    }

    [[nodiscard]] const std::vector<HeaderField>& Fields() const noexcept
    {
        return m_fields;
    }

    void Fields(std::vector<HeaderField> fields)
    {
        m_fields = std::move(fields);
    }

    void AddField(HeaderField field)
    {
        m_fields.push_back(std::move(field));
    }

    [[nodiscard]] std::optional<std::string_view> SingleField(std::string_view name) const;
    void RemoveField(std::string_view name);
    void RemoveHopByHopFields();
    void ValidateFraming() const;
    // Framing is explicit in Fields, never inferred from buffered body data.
    [[nodiscard]] std::string Encode() const;

private:
    MessageKind m_kind = MessageKind::Request;
    unsigned m_version = 11;
    std::string m_method;
    std::string m_target;
    unsigned m_status = 200;
    std::string m_reason;
    std::vector<HeaderField> m_fields;
};

struct ParserOptions
{
    MessageKind Kind = MessageKind::Request;
    std::uint32_t HeaderLimit = 32U * 1024U;
    std::uint64_t BodyLimit = std::numeric_limits<std::uint64_t>::max();
    bool SkipBody = false;
};

struct ParseProgress
{
    std::size_t Consumed = 0;
    std::size_t BodyBytes = 0;
};

enum class MessageErrorKind
{
    Malformed,
    HeaderLimit,
    BodyLimit,
    Truncated,
    InvalidState,
};

class MessageError final : public std::exception
{
public:
    explicit MessageError(MessageErrorKind kind) noexcept;
    [[nodiscard]] MessageErrorKind Kind() const noexcept;
    [[nodiscard]] const char* what() const noexcept override;

private:
    MessageErrorKind m_kind;
};

class MessageParser
{
public:
    virtual ~MessageParser();
    // Retain unconsumed bytes and append more input when no progress is made. Parsing pauses
    // at the header boundary so routing/authorization can run before any body is consumed.
    [[nodiscard]] virtual ParseProgress Put(std::span<const std::uint8_t> input,
                                            std::span<std::uint8_t> body) = 0;
    virtual void Finish() = 0;
    [[nodiscard]] virtual bool HeaderComplete() const noexcept = 0;
    [[nodiscard]] virtual bool Complete() const noexcept = 0;
    // Includes the parsed HTTP version, Connection tokens and self-delimiting framing.
    [[nodiscard]] virtual bool KeepAlive() const noexcept = 0;
    [[nodiscard]] virtual const MessageHead& Head() const = 0;
    [[nodiscard]] virtual std::vector<HeaderField> Trailers() const = 0;
    // Decode a finite response, including informational responses before the final one.
    [[nodiscard]] Response DecodeResponse(std::string_view encoded);

protected:
    virtual void Reset() = 0;
};

class MessageParserFactory
{
public:
    virtual ~MessageParserFactory();
    [[nodiscard]] virtual std::unique_ptr<MessageParser> Create(const ParserOptions& options) = 0;
};

class ChunkEncoder final
{
public:
    [[nodiscard]] static std::string Encode(std::span<const std::uint8_t> body);
    [[nodiscard]] static std::string EncodeLast(const std::vector<HeaderField>& trailers = {});
};

} // namespace tailgate::net::http
