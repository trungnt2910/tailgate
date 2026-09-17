#include "tailgate/net/http/Message.h"

#include <array>
#include <cctype>
#include <span>

#include <tailgate/net/http/Client.h>

namespace tailgate::net::http
{

MessageParser::~MessageParser() = default;
MessageParserFactory::~MessageParserFactory() = default;

Response MessageParser::DecodeResponse(std::string_view encoded)
{
    if (HeaderComplete() || Complete())
    {
        throw MessageError(MessageErrorKind::InvalidState);
    }
    const auto input =
        std::span(reinterpret_cast<const std::uint8_t*>(encoded.data()), encoded.size());
    std::array<std::uint8_t, 16U * 1024U> chunk{};
    std::string body;
    std::size_t offset = 0;
    constexpr unsigned MaximumInformationalResponses = 16;
    unsigned informational = 0;
    while (true)
    {
        if (offset == input.size())
        {
            Finish();
        }
        else if (!Complete())
        {
            const auto progress = Put(input.subspan(offset), chunk);
            offset += progress.Consumed;
            body.append(reinterpret_cast<const char*>(chunk.data()), progress.BodyBytes);
            if (progress.Consumed == 0 && progress.BodyBytes == 0 && !Complete())
            {
                throw MessageError(MessageErrorKind::Truncated);
            }
        }
        if (!Complete())
        {
            continue;
        }
        if (Head().Kind() != MessageKind::Response)
        {
            throw MessageError(MessageErrorKind::InvalidState);
        }
        const auto status = Head().Status();
        (void)Trailers();
        if (status >= 100 && status < 200 && status != 101)
        {
            if (++informational > MaximumInformationalResponses)
            {
                throw MessageError(MessageErrorKind::Malformed);
            }
            Reset();
            continue;
        }
        std::map<std::string, std::string> headers;
        for (const auto& field : Head().Fields())
        {
            auto name = field.Name();
            for (auto& character : name)
            {
                character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
            }
            auto [found, inserted] = headers.emplace(std::move(name), field.Value());
            if (!inserted)
            {
                found->second += ", " + field.Value();
            }
        }
        return Response(static_cast<int>(status), std::move(headers), std::move(body));
    }
}

} // namespace tailgate::net::http
