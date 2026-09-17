#include "MessageParserFactoryImpl.h"

#include <algorithm>
#include <exception>
#include <optional>

#include <llhttp.h>

namespace tailgate::net::http::impl
{
namespace
{

class Parser final : public MessageParser
{
public:
    explicit Parser(const ParserOptions& options) : m_options(options)
    {
        llhttp_settings_init(&m_settings);
        m_settings.on_url = DataCallback<&Parser::Target>;
        m_settings.on_status = DataCallback<&Parser::Reason>;
        m_settings.on_header_field = DataCallback<&Parser::FieldName>;
        m_settings.on_header_value = DataCallback<&Parser::FieldValue>;
        m_settings.on_header_value_complete = Callback<&Parser::FieldComplete>;
        m_settings.on_headers_complete = Callback<&Parser::HeadersComplete>;
        m_settings.on_chunk_header = Callback<&Parser::ChunkHeader>;
        m_settings.on_chunk_complete = Callback<&Parser::ChunkComplete>;
        m_settings.on_body = DataCallback<&Parser::Body>;
        m_settings.on_message_complete = Callback<&Parser::MessageComplete>;
        Reset();
    }

    ParseProgress Put(std::span<const std::uint8_t> input, std::span<std::uint8_t> body) override
    {
        if (m_failed || Complete())
        {
            throw MessageError(MessageErrorKind::InvalidState);
        }
        m_output = body;
        ParseProgress progress;
        try
        {
            while (!input.empty() && !Complete())
            {
                const auto phase = m_phase;
                std::size_t size = input.size();
                if (phase == Phase::Body)
                {
                    size = std::min(size, m_output.size());
                    if (m_remaining)
                    {
                        size =
                            static_cast<std::size_t>(std::min<std::uint64_t>(size, *m_remaining));
                    }
                    if (size == 0)
                    {
                        break;
                    }
                }
                else if (phase == Phase::ChunkSuffix)
                {
                    constexpr std::size_t CrLfSize = 2;
                    if (size < CrLfSize)
                    {
                        break;
                    }
                    size = CrLfSize;
                }
                else
                {
                    // Bound callback allocations, including fragmented headers, trailers and
                    // chunk extensions. The extra byte detects an exceeded limit promptly.
                    size = static_cast<std::size_t>(
                        std::min<std::uint64_t>(size, m_options.HeaderLimit - m_metadataBytes + 1));
                }
                const auto consumed = Execute(reinterpret_cast<const char*>(input.data()), size);
                if (phase != Phase::Body)
                {
                    m_metadataBytes += consumed;
                    if (m_metadataBytes > m_options.HeaderLimit)
                    {
                        throw MessageError(MessageErrorKind::HeaderLimit);
                    }
                    if (phase != m_phase)
                    {
                        m_metadataBytes = 0;
                    }
                }
                input = input.subspan(consumed);
                progress.Consumed += consumed;
                if (phase == Phase::Head && HeaderComplete())
                {
                    // Advance the post-header state without offering any body bytes. This
                    // completes empty/HEAD/upgrade messages within the same Put call.
                    (void)Execute("", 0);
                    break;
                }
                if (consumed == 0 && phase == m_phase)
                {
                    break;
                }
            }
            progress.BodyBytes = body.size() - m_output.size();
            m_output = {};
            return progress;
        }
        catch (...)
        {
            m_output = {};
            m_failed = true;
            throw;
        }
    }

    void Finish() override
    {
        if (m_failed)
        {
            throw MessageError(MessageErrorKind::InvalidState);
        }
        if (Complete())
        {
            return;
        }
        try
        {
            if (!HeaderComplete())
            {
                throw MessageError(MessageErrorKind::Truncated);
            }
            (void)Execute("", 0);
            Check(llhttp_finish(&m_parser));
            if (!Complete())
            {
                throw MessageError(MessageErrorKind::Truncated);
            }
        }
        catch (...)
        {
            m_failed = true;
            throw;
        }
    }

    bool HeaderComplete() const noexcept override
    {
        return m_headerComplete;
    }

    bool Complete() const noexcept override
    {
        return !m_failed && m_complete;
    }

    bool KeepAlive() const noexcept override
    {
        return !m_failed && HeaderComplete() && m_keepAlive;
    }

    const MessageHead& Head() const override
    {
        if (!HeaderComplete())
        {
            throw MessageError(MessageErrorKind::InvalidState);
        }
        return m_head;
    }

    std::vector<HeaderField> Trailers() const override
    {
        if (!Complete())
        {
            throw MessageError(MessageErrorKind::InvalidState);
        }
        for (const auto& field : m_trailers)
        {
            field.ValidateTrailer();
        }
        return m_trailers;
    }

private:
    enum class Phase
    {
        Head,
        Body,
        ChunkFraming,
        ChunkSuffix,
        Trailers,
    };

    void Reset() override
    {
        llhttp_init(&m_parser,
                    m_options.Kind == MessageKind::Request ? HTTP_REQUEST : HTTP_RESPONSE,
                    &m_settings);
        m_parser.data = this;
        m_head = MessageHead{};
        m_head.Kind(m_options.Kind);
        m_target.clear();
        m_reason.clear();
        m_fieldName.clear();
        m_fieldValue.clear();
        m_trailers.clear();
        m_output = {};
        m_remaining.reset();
        m_exception = nullptr;
        m_metadataBytes = 0;
        m_bodyBytes = 0;
        m_phase = Phase::Head;
        m_headerComplete = false;
        m_complete = false;
        m_keepAlive = false;
        m_failed = false;
    }

    template <auto Function>
    static int Callback(llhttp_t* parser) noexcept
    {
        auto& self = *static_cast<Parser*>(parser->data);
        try
        {
            return (self.*Function)();
        }
        catch (...)
        {
            // Never unwind through the generated C parser, especially across the UWP ABI.
            self.m_exception = std::current_exception();
            return HPE_USER;
        }
    }

    template <auto Function>
    static int DataCallback(llhttp_t* parser, const char* data, std::size_t size) noexcept
    {
        auto& self = *static_cast<Parser*>(parser->data);
        try
        {
            return (self.*Function)(std::string_view(data, size));
        }
        catch (...)
        {
            self.m_exception = std::current_exception();
            return HPE_USER;
        }
    }

    void Check(llhttp_errno_t error)
    {
        if (m_exception)
        {
            std::rethrow_exception(m_exception);
        }
        if (error == HPE_OK || error == HPE_PAUSED || error == HPE_PAUSED_UPGRADE)
        {
            return;
        }
        throw MessageError(error == HPE_INVALID_EOF_STATE ? MessageErrorKind::Truncated
                                                          : MessageErrorKind::Malformed);
    }

    std::size_t Execute(const char* data, std::size_t size)
    {
        if (llhttp_get_errno(&m_parser) == HPE_PAUSED)
        {
            llhttp_resume(&m_parser);
        }
        const auto error = llhttp_execute(&m_parser, data, size);
        Check(error);
        return error == HPE_OK ? size
                               : static_cast<std::size_t>(llhttp_get_error_pos(&m_parser) - data);
    }

    int Target(std::string_view data)
    {
        m_target.append(data);
        return HPE_OK;
    }

    int Reason(std::string_view data)
    {
        m_reason.append(data);
        return HPE_OK;
    }

    int FieldName(std::string_view data)
    {
        m_fieldName.append(data);
        return HPE_OK;
    }

    int FieldValue(std::string_view data)
    {
        m_fieldValue.append(data);
        return HPE_OK;
    }

    int FieldComplete()
    {
        // llhttp removes leading OWS; field values exposed by the codec omit trailing OWS too.
        const auto last = m_fieldValue.find_last_not_of(" \t");
        m_fieldValue.resize(last == std::string::npos ? 0 : last + 1);
        HeaderField field(std::move(m_fieldName), std::move(m_fieldValue));
        m_fieldName.clear();
        m_fieldValue.clear();
        if (m_phase == Phase::Trailers)
        {
            m_trailers.push_back(std::move(field));
        }
        else
        {
            m_head.AddField(std::move(field));
        }
        return HPE_OK;
    }

    int HeadersComplete()
    {
        if (m_parser.http_major != 1 || m_parser.http_minor > 1)
        {
            throw MessageError(MessageErrorKind::Malformed);
        }
        m_head.Version(10 + m_parser.http_minor);
        if (m_options.Kind == MessageKind::Request)
        {
            m_head.Method(llhttp_method_name(static_cast<llhttp_method_t>(m_parser.method)));
            m_head.Target(std::move(m_target));
        }
        else
        {
            m_head.Status(m_parser.status_code);
            m_head.Reason(std::move(m_reason));
        }
        m_head.ValidateFraming();
        const bool bodylessStatus =
            m_options.Kind == MessageKind::Response &&
            (m_head.Status() / 100 == 1 || m_head.Status() == 204 || m_head.Status() == 304);
        if (m_options.SkipBody || bodylessStatus)
        {
            m_parser.flags |= F_SKIPBODY;
        }
        else if ((m_parser.flags & F_CONTENT_LENGTH) != 0)
        {
            if (m_parser.content_length > m_options.BodyLimit)
            {
                throw MessageError(MessageErrorKind::BodyLimit);
            }
            m_remaining = m_parser.content_length;
        }
        m_phase = (m_parser.flags & F_CHUNKED) != 0 ? Phase::ChunkFraming : Phase::Body;
        m_keepAlive = llhttp_should_keep_alive(&m_parser) != 0;
        m_headerComplete = true;
        return HPE_PAUSED;
    }

    int ChunkHeader()
    {
        m_remaining = m_parser.content_length;
        if (*m_remaining > m_options.BodyLimit - m_bodyBytes)
        {
            throw MessageError(MessageErrorKind::BodyLimit);
        }
        m_phase = *m_remaining == 0 ? Phase::Trailers : Phase::Body;
        // Pause before chunk data so the next execute is limited by the output capacity.
        return HPE_PAUSED;
    }

    int ChunkComplete()
    {
        if (m_phase == Phase::ChunkSuffix)
        {
            m_phase = Phase::ChunkFraming;
        }
        return HPE_OK;
    }

    int Body(std::string_view data)
    {
        if (data.size() > m_options.BodyLimit - m_bodyBytes)
        {
            throw MessageError(MessageErrorKind::BodyLimit);
        }
        if (data.size() > m_output.size())
        {
            throw MessageError(MessageErrorKind::InvalidState);
        }
        std::ranges::copy(data, m_output.begin());
        m_output = m_output.subspan(data.size());
        m_bodyBytes += data.size();
        if (m_remaining)
        {
            *m_remaining -= data.size();
            if (*m_remaining == 0 && (m_parser.flags & F_CHUNKED) != 0)
            {
                m_phase = Phase::ChunkSuffix;
            }
        }
        return HPE_OK;
    }

    int MessageComplete()
    {
        m_complete = true;
        // Preserve the next message (or upgraded protocol) in the caller's input buffer.
        return HPE_PAUSED;
    }

    ParserOptions m_options;
    llhttp_settings_t m_settings{};
    llhttp_t m_parser{};
    MessageHead m_head;
    std::string m_target;
    std::string m_reason;
    std::string m_fieldName;
    std::string m_fieldValue;
    std::vector<HeaderField> m_trailers;
    std::span<std::uint8_t> m_output;
    std::optional<std::uint64_t> m_remaining;
    std::exception_ptr m_exception;
    std::uint64_t m_metadataBytes = 0;
    std::uint64_t m_bodyBytes = 0;
    Phase m_phase = Phase::Head;
    bool m_headerComplete = false;
    bool m_complete = false;
    bool m_keepAlive = false;
    bool m_failed = false;
};

} // namespace

std::unique_ptr<MessageParser> MessageParserFactoryImpl::Create(const ParserOptions& options)
{
    return std::make_unique<Parser>(options);
}

} // namespace tailgate::net::http::impl
