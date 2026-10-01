#pragma once

#include <chrono>
#include <optional>
#include <stop_token>
#include <string>

#include <tailgate/base/ByteStream.h>

namespace tailgate::linux_frontend::impl
{

class TcpStream final : public tailgate::base::ByteStream
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
              int connectTimeoutSeconds = 0,
              std::stop_token cancellation = {});
    ~TcpStream() override;

    TcpStream(const TcpStream&) = delete;
    TcpStream& operator=(const TcpStream&) = delete;

    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                          std::size_t size) override;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maxBytes) override;
    [[nodiscard]] int NativeHandle() const;
    void SetReadTimeout(std::optional<std::chrono::seconds> timeout);
    void SetNonBlocking(bool enabled);

private:
    int m_fd = -1;
    std::stop_token m_cancellation;
    std::optional<std::chrono::seconds> m_readTimeout;
    std::chrono::seconds m_writeTimeout;
    bool m_nonBlocking = false;
};

} // namespace tailgate::linux_frontend::impl
