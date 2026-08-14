#pragma once

#include <memory>
#include <string>
#include <vector>

#include <tailgate/base/ByteStream.h>

namespace tailgate::net::tls
{

class TlsStream final : public tailgate::base::IByteStream
{
public:
    TlsStream(tailgate::base::IByteStream& transport,
              const std::string& hostname,
              const std::vector<std::uint8_t>& caPem,
              bool allowTls13 = false);
    ~TlsStream() override;
    TlsStream(const TlsStream&) = delete;
    TlsStream& operator=(const TlsStream&) = delete;

    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                          std::size_t size) override;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maxBytes) override;
    [[nodiscard]] bool HasBufferedInput() const override;
    [[nodiscard]] bool ReadNeedsWrite() const override;
    [[nodiscard]] bool WriteNeedsRead() const override;

private:
    class Impl;
    std::unique_ptr<Impl> Implementation;
};

} // namespace tailgate::net::tls
