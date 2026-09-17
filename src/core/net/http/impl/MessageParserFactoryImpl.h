#pragma once

#include <tailgate/net/http/Message.h>

namespace tailgate::net::http::impl
{

class MessageParserFactoryImpl final : public MessageParserFactory
{
public:
    [[nodiscard]] std::unique_ptr<MessageParser> Create(const ParserOptions& options) override;
};

} // namespace tailgate::net::http::impl
