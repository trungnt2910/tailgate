#pragma once

#include "tailgate/ByteStream.h"

#include <string>

namespace tailgate::linux_frontend
{

class TcpStream final : public IByteStream
{
public:
    static constexpr int DefaultIoTimeoutSeconds = 15;
    static constexpr int ControlIoTimeoutSeconds = 60;

    // A zero connect timeout uses the I/O timeout. A short connect timeout lets dial-with-
    // fallback strategies abandon an unresponsive endpoint quickly while keeping long steady-
    // state read timeouts.
    TcpStream(const std::string& host,
              const std::string& service,
              const std::string& interfaceName = {},
              int ioTimeoutSeconds = DefaultIoTimeoutSeconds,
              int connectTimeoutSeconds = 0);
    ~TcpStream() override;

    TcpStream(const TcpStream&) = delete;
    TcpStream& operator=(const TcpStream&) = delete;

    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                          std::size_t size) override;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maxBytes) override;
    [[nodiscard]] int NativeHandle() const;
    void SetNonBlocking(bool enabled);

private:
    int m_fd = -1;
};

} // namespace tailgate::linux_frontend
