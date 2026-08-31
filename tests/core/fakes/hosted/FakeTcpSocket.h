#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::tests::fakes::hosted
{

class FakeTcpSocket final : public tailgate::types::nettype::TcpSocket
{
public:
    FakeTcpSocket(tailgate::crypto::Bytes32 relayPrivateKey,
                  tailgate::crypto::Bytes32 serverNonce,
                  bool reject)
        : RelayPrivateKey(relayPrivateKey), ServerNonce(serverNonce), Reject(reject)
    {
        const tailgate::crypto::Bytes32 relayPublicKey =
            tailgate::crypto::X25519PublicFromPrivate(RelayPrivateKey);
        const std::string upgrade = "HTTP/1.1 101 Switching Protocols\r\n"
                                    "Connection: Upgrade\r\n"
                                    "Upgrade: tailgate\r\n\r\n";
        Input.assign(upgrade.begin(), upgrade.end());
        const std::vector<std::uint8_t> challenge =
            tailgate::hosted::Frame(tailgate::hosted::MessageType::ServerChallenge,
                                    tailgate::hosted::ProtocolCodec::EncodeChallenge(
                                        tailgate::hosted::Challenge(relayPublicKey, ServerNonce)))
                .Encode();
        Input.insert(Input.end(), challenge.begin(), challenge.end());
    }

    std::optional<std::size_t> TryWriteSome(const std::uint8_t* data, std::size_t size) override
    {
        Output.insert(Output.end(), data, data + size);
        ++WriteCount;
        if (WriteCount == 2)
        {
            RespondToAuthentication(data, size);
        }
        return size;
    }

    std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t maximumSize) override
    {
        const std::size_t count = std::min(maximumSize, Input.size() - Offset);
        std::vector<std::uint8_t> result(Input.begin() + static_cast<std::ptrdiff_t>(Offset),
                                         Input.begin() +
                                             static_cast<std::ptrdiff_t>(Offset + count));
        Offset += count;
        return result;
    }

    void SetWriteInterest(bool) override
    {
    }

    void SetReadTimeout(std::optional<std::chrono::seconds>) override
    {
    }

    void SetNonBlocking(bool enabled) override
    {
        NonBlocking = enabled;
    }

    void Close() noexcept override
    {
    }

    [[nodiscard]] const std::vector<std::uint8_t>& WrittenBytes() const noexcept
    {
        return Output;
    }

    [[nodiscard]] bool IsNonBlocking() const noexcept
    {
        return NonBlocking;
    }

private:
    void RespondToAuthentication(const std::uint8_t* data, std::size_t size)
    {
        tailgate::hosted::Decoder decoder;
        decoder.Feed(data, size);
        const std::optional<tailgate::hosted::Frame> frame = decoder.Next();
        if (!frame || frame->Type() != tailgate::hosted::MessageType::Authenticate)
        {
            return;
        }
        const tailgate::hosted::Authentication authentication =
            tailgate::hosted::ProtocolCodec::DecodeAuthentication(frame->Payload());
        const tailgate::hosted::Frame response =
            Reject ? tailgate::hosted::Frame(tailgate::hosted::MessageType::Rejected,
                                             tailgate::hosted::ProtocolCodec::EncodeRejection(
                                                 tailgate::hosted::Rejection("fake rejection")))
                   : tailgate::hosted::Frame(
                         tailgate::hosted::MessageType::Authenticated,
                         tailgate::hosted::ProtocolCodec::EncodeSession(tailgate::hosted::Session(
                             authentication.Tailnet(),
                             "relay.example.ts.net",
                             "192.0.2.1",
                             tailgate::hosted::CreateServerProof(RelayPrivateKey,
                                                                 authentication.NodePublicKey(),
                                                                 ServerNonce,
                                                                 authentication.ClientNonce()))));
        std::vector<std::uint8_t> encoded = response.Encode();
        Input.insert(Input.end(), encoded.begin(), encoded.end());
    }

    tailgate::crypto::Bytes32 RelayPrivateKey{};
    tailgate::crypto::Bytes32 ServerNonce{};
    bool Reject = false;
    std::vector<std::uint8_t> Input;
    std::vector<std::uint8_t> Output;
    std::size_t Offset = 0;
    std::size_t WriteCount = 0;
    bool NonBlocking = false;
};

class FakeTcpSocketFactory final : public tailgate::types::nettype::TcpSocketFactory
{
public:
    FakeTcpSocketFactory(tailgate::crypto::Bytes32 relayPrivateKey,
                         tailgate::crypto::Bytes32 serverNonce,
                         bool reject)
        : RelayPrivateKey(relayPrivateKey), ServerNonce(serverNonce), Reject(reject)
    {
    }

    std::unique_ptr<tailgate::types::nettype::TcpSocket>
    OpenTcpSocket(const tailgate::types::nettype::TcpSocketOptions& options) override
    {
        Options = options;
        return std::make_unique<FakeTcpSocket>(RelayPrivateKey, ServerNonce, Reject);
    }

    tailgate::crypto::Bytes32 RelayPrivateKey{};
    tailgate::crypto::Bytes32 ServerNonce{};
    bool Reject = false;
    std::optional<tailgate::types::nettype::TcpSocketOptions> Options;
};

} // namespace tailgate::tests::fakes::hosted
