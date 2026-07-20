#pragma once

#include "tailgate/ByteStream.h"
#include "tailgate/Logging.h"

#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace tailgate::control
{

// Outcome of a control dial: the winning transport and whether the TLS fallback was used.
template <typename StreamPointer>
struct ControlDialOutcome
{
    StreamPointer Stream;
    bool UsedTls = false;
};

// Connects to the control server like the official client: the ts2021 Noise handshake pins the
// control server's public key, so the plaintext HTTP endpoint is just as authenticated as TLS
// and is preferred. TLS remains a compatibility fallback for networks that block or tamper with
// the plaintext upgrade. The official client races both dials with a short plaintext head
// start; this sequential variant bounds the plaintext attempt with the factory's own connect
// timeout instead, then falls back.
//
// `plaintext` and `tls` return a connected transport or throw. `establish` must run the ts2021
// upgrade and Noise handshake over the given stream (typically by constructing the
// ControlClient), throwing on failure so the dial can fall back to TLS.
template <typename PlainFactory, typename TlsFactory, typename Establish>
[[nodiscard]] auto
DialControlStream(const PlainFactory& plaintext, const TlsFactory& tls, const Establish& establish)
    -> ControlDialOutcome<decltype(plaintext())>
{
    static_assert(std::is_same_v<decltype(plaintext()), decltype(tls())>,
                  "both control stream factories must produce the same stream type");
    try
    {
        auto stream = plaintext();
        establish(*stream);
        return ControlDialOutcome<decltype(plaintext())>{.Stream = std::move(stream),
                                                         .UsedTls = false};
    }
    catch (const std::exception& error)
    {
        Log(LogLevel::Warning,
            "control",
            std::string("plaintext control connection failed (") + error.what() +
                "); falling back to TLS");
    }
    auto stream = tls();
    establish(*stream);
    return ControlDialOutcome<decltype(plaintext())>{.Stream = std::move(stream), .UsedTls = true};
}

} // namespace tailgate::control
