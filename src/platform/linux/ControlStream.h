#pragma once

#include <functional>
#include <memory>
#include <string>

#include <tailgate/ByteStream.h>
#include <tailgate/protocol/TlsStream.h>

#include "TcpStream.h"

namespace tailgate::linux_frontend
{

// Control transport that is either the plaintext ts2021 endpoint or its TLS fallback. Both
// layers are owned so the winner of the control dial can outlive the dialing scope.
class ControlStream final : public IByteStream
{
public:
    ControlStream(const std::string& interfaceName, bool useTls);

    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                          std::size_t size) override;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maxBytes) override;
    [[nodiscard]] bool HasBufferedInput() const override;
    [[nodiscard]] bool ReadNeedsWrite() const override;
    [[nodiscard]] bool WriteNeedsRead() const override;
    [[nodiscard]] int NativeHandle() const;
    void SetNonBlocking(bool enabled);

private:
    [[nodiscard]] IByteStream& Active();
    [[nodiscard]] const IByteStream& Active() const;

    TcpStream m_transport;
    std::unique_ptr<protocol::TlsStream> m_tls;
};

struct DialedControlStream
{
    std::unique_ptr<ControlStream> Stream;
    bool UsedTls = false;
};

// Dials control with the shared plaintext-first policy (control::DialControlStream).
// `establish` must run the ts2021 upgrade and Noise handshake over the stream, typically by
// constructing the ControlClient, and throw on failure so the dial can fall back to TLS.
[[nodiscard]] DialedControlStream DialControl(const std::string& interfaceName,
                                              const std::function<void(IByteStream&)>& establish);

} // namespace tailgate::linux_frontend
