#pragma once

#include "tailgate/ByteStream.h"

#include <memory>
#include <string>
#include <vector>

namespace tailgate::protocol
{

class TlsStream final : public IByteStream
{
public:
    TlsStream(IByteStream& transport,
              const std::string& hostname,
              const std::vector<std::uint8_t>& caPem);
    ~TlsStream() override;
    TlsStream(const TlsStream&) = delete;
    TlsStream& operator=(const TlsStream&) = delete;

    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                          std::size_t size) override;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maxBytes) override;
    [[nodiscard]] bool HasBufferedInput() const override;

private:
    class Impl;
    std::unique_ptr<Impl> Implementation;
};

} // namespace tailgate::protocol
