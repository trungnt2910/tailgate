#include <tailgate/wgengine/wireguard/Tunnel.h>

#include <algorithm>
#include <cstring>
#include <format>
#include <stdexcept>

#include <sodium.h>

extern "C"
{
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include "wireguard.h"
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
}

#include <tailgate/base/Logging.h>
#include <tailgate/wgengine/wireguard/ReplayWindow.h>

namespace tailgate::wgengine::wireguard
{

using tailgate::base::Log;
using tailgate::base::LogLevel;

namespace
{

constexpr std::size_t WireGuardCounterSize = 8;
constexpr std::size_t WireGuardPaddingAlignment = 16;
constexpr std::uint8_t Ipv4Version = 4;
constexpr std::uint8_t Ipv6Version = 6;
constexpr std::size_t Ipv4MinimumHeaderSize = 4;
constexpr std::size_t Ipv6MinimumHeaderSize = 6;
constexpr std::size_t Ipv6HeaderSize = 40;
constexpr std::size_t WireGuardNonceSize = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;

std::uint64_t ReadCounter(const std::uint8_t* bytes)
{
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < WireGuardCounterSize; ++index)
    {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8);
    }
    return value;
}

void WriteCounter(std::uint8_t* bytes, std::uint64_t value)
{
    for (std::size_t index = 0; index < WireGuardCounterSize; ++index)
    {
        bytes[index] = static_cast<std::uint8_t>(value >> (index * 8));
    }
}

void EnsureSodium()
{
    static const bool initialized = []()
    {
        if (sodium_init() < 0)
        {
            throw std::runtime_error("Libsodium initialization failed.");
        }
        return true;
    }();
    (void)initialized;
}

std::array<std::uint8_t, WireGuardNonceSize> TransportNonce(std::uint64_t counter)
{
    std::array<std::uint8_t, WireGuardNonceSize> nonce{};
    WriteCounter(nonce.data() + 4, counter);
    return nonce;
}

void EncryptTransport(std::uint8_t* output,
                      const std::uint8_t* input,
                      std::size_t inputSize,
                      wireguard_keypair& keypair)
{
    EnsureSodium();
    constexpr std::uint8_t EmptyPayload = 0;
    const std::uint8_t* plaintext = inputSize == 0 ? &EmptyPayload : input;
    const auto nonce = TransportNonce(keypair.sending_counter);
    unsigned long long encryptedSize = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(output,
                                                  &encryptedSize,
                                                  plaintext,
                                                  static_cast<unsigned long long>(inputSize),
                                                  nullptr,
                                                  0,
                                                  nullptr,
                                                  nonce.data(),
                                                  keypair.sending_key) != 0 ||
        encryptedSize != inputSize + WIREGUARD_AUTHTAG_LEN)
    {
        throw std::runtime_error("WireGuard transport encryption failed.");
    }
    ++keypair.sending_counter;
}

bool DecryptTransport(std::uint8_t* output,
                      const std::uint8_t* input,
                      std::size_t inputSize,
                      std::uint64_t counter,
                      const wireguard_keypair& keypair)
{
    EnsureSodium();
    std::uint8_t emptyPlaintext = 0;
    std::uint8_t* plaintext = inputSize == WIREGUARD_AUTHTAG_LEN ? &emptyPlaintext : output;
    const auto nonce = TransportNonce(counter);
    unsigned long long decryptedSize = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(plaintext,
                                                  &decryptedSize,
                                                  nullptr,
                                                  input,
                                                  static_cast<unsigned long long>(inputSize),
                                                  nullptr,
                                                  0,
                                                  nonce.data(),
                                                  keypair.receiving_key) != 0)
    {
        return false;
    }
    return decryptedSize + WIREGUARD_AUTHTAG_LEN == inputSize;
}

wireguard_keypair* FindSendingKeypair(wireguard_peer& peer)
{
    wireguard_keypair* keypair = &peer.curr_keypair;
    if (keypair->valid && !keypair->initiator && keypair->last_rx == 0)
    {
        keypair = &peer.prev_keypair;
    }
    if (!keypair->valid || (!keypair->initiator && keypair->last_rx == 0) ||
        wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME) ||
        keypair->sending_counter >= REJECT_AFTER_MESSAGES)
    {
        return nullptr;
    }
    return keypair;
}

const wireguard_keypair* FindSendingKeypair(const wireguard_peer& peer)
{
    const wireguard_keypair* keypair = &peer.curr_keypair;
    if (keypair->valid && !keypair->initiator && keypair->last_rx == 0)
    {
        keypair = &peer.prev_keypair;
    }
    if (!keypair->valid || (!keypair->initiator && keypair->last_rx == 0) ||
        wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME) ||
        keypair->sending_counter >= REJECT_AFTER_MESSAGES)
    {
        return nullptr;
    }
    return keypair;
}

} // namespace

class WireGuardTunnel::Impl
{
public:
    struct PeerReference
    {
        struct SessionReplay
        {
            std::uint32_t LocalIndex = 0;
            std::uint32_t StartedAt = 0;
            ReplayWindow Window;
        };

        wireguard_device* Device;
        wireguard_peer* Peer;
        std::vector<SessionReplay> ReplaySessions;

        ReplayWindow& ReplayFor(const wireguard_keypair& keypair)
        {
            auto found = std::find_if(ReplaySessions.begin(),
                                      ReplaySessions.end(),
                                      [&](const SessionReplay& session)
                                      {
                                          return session.LocalIndex == keypair.local_index &&
                                                 session.StartedAt == keypair.keypair_millis;
                                      });
            if (found != ReplaySessions.end())
            {
                return found->Window;
            }
            constexpr std::size_t maximumRetainedSessions = 3;
            if (ReplaySessions.size() == maximumRetainedSessions)
            {
                ReplaySessions.erase(ReplaySessions.begin());
            }
            ReplaySessions.push_back(SessionReplay{.LocalIndex = keypair.local_index,
                                                   .StartedAt = keypair.keypair_millis,
                                                   .Window = {}});
            return ReplaySessions.back().Window;
        }
    };

    explicit Impl(const Key& privateKey) : PrivateKey(privateKey)
    {
        wireguard_init();
        AddDevice();
    }

    wireguard_device& AddDevice()
    {
        auto device = std::make_unique<wireguard_device>();
        if (!wireguard_device_init(device.get(), PrivateKey.data()))
        {
            throw std::runtime_error("Failed to initialize WireGuard device.");
        }
        Devices.push_back(std::move(device));
        return *Devices.back();
    }

    PeerReference& GetPeer(PeerId id)
    {
        if (id >= Peers.size() || Peers[id].Peer == nullptr)
        {
            throw std::out_of_range("Invalid WireGuard peer.");
        }
        return Peers[id];
    }

    const PeerReference& GetPeer(PeerId id) const
    {
        if (id >= Peers.size() || Peers[id].Peer == nullptr)
        {
            throw std::out_of_range("Invalid WireGuard peer.");
        }
        return Peers[id];
    }

    Key PrivateKey;
    std::vector<std::unique_ptr<wireguard_device>> Devices;
    std::vector<PeerReference> Peers;
};

WireGuardTunnel::WireGuardTunnel(const Key& privateKey)
    : Implementation(std::make_unique<Impl>(privateKey))
{
}

WireGuardTunnel::~WireGuardTunnel() = default;
WireGuardTunnel::WireGuardTunnel(WireGuardTunnel&&) noexcept = default;
WireGuardTunnel& WireGuardTunnel::operator=(WireGuardTunnel&&) noexcept = default;

WireGuardTunnel::PeerId WireGuardTunnel::AddPeer(const Key& publicKey,
                                                 const Key& presharedKey,
                                                 std::uint16_t keepalive,
                                                 bool initiateAutomatically)
{
    wireguard_device* device = Implementation->Devices.back().get();
    wireguard_peer* peer = peer_alloc(device);
    if (peer == nullptr)
    {
        device = &Implementation->AddDevice();
        peer = peer_alloc(device);
    }
    if (peer == nullptr ||
        !wireguard_peer_init(device, peer, publicKey.data(), presharedKey.data()))
    {
        throw std::runtime_error("Failed to initialize WireGuard peer.");
    }
    peer->active = initiateAutomatically;
    peer->keepalive_interval = keepalive;
    Implementation->Peers.push_back(
        Impl::PeerReference{.Device = device, .Peer = peer, .ReplaySessions = {}});
    return Implementation->Peers.size() - 1;
}

std::vector<std::uint8_t> WireGuardTunnel::CreateHandshake(PeerId peerId)
{
    Impl::PeerReference& reference = Implementation->GetPeer(peerId);
    wireguard_peer& peer = *reference.Peer;
    message_handshake_initiation message{};
    if (!wireguard_create_handshake_initiation(reference.Device, &peer, &message))
    {
        throw std::runtime_error("Failed to create WireGuard handshake.");
    }
    peer.send_handshake = false;
    peer.last_initiation_tx = wireguard_sys_now();
    return {reinterpret_cast<const std::uint8_t*>(&message),
            reinterpret_cast<const std::uint8_t*>(&message) + sizeof(message)};
}

std::optional<WireGuardTunnel::ReceivedPacket>
WireGuardTunnel::ProcessPacket(PeerId peerId, const std::vector<std::uint8_t>& packet)
{
    Impl::PeerReference& reference = Implementation->GetPeer(peerId);
    wireguard_peer& peer = *reference.Peer;
    const std::uint8_t type = wireguard_get_message_type(packet.data(), packet.size());
    if (type == MESSAGE_HANDSHAKE_INITIATION &&
        packet.size() == sizeof(message_handshake_initiation))
    {
        message_handshake_initiation initiation{};
        std::memcpy(&initiation, packet.data(), sizeof(initiation));
        wireguard_peer* initiatingPeer =
            wireguard_process_initiation_message(reference.Device, &initiation);
        if (initiatingPeer != &peer)
        {
            return std::nullopt;
        }

        message_handshake_response response{};
        if (!wireguard_create_handshake_response(reference.Device, &peer, &response))
        {
            return std::nullopt;
        }
        wireguard_start_session(&peer, false);
        return ReceivedPacket{
            .Peer = peerId,
            .Plaintext = {},
            .Reply = {reinterpret_cast<const std::uint8_t*>(&response),
                      reinterpret_cast<const std::uint8_t*>(&response) + sizeof(response)},
            .SessionEstablished = true};
    }
    if (type == MESSAGE_HANDSHAKE_RESPONSE && packet.size() == sizeof(message_handshake_response))
    {
        message_handshake_response response{};
        std::memcpy(&response, packet.data(), sizeof(response));
        if (!wireguard_process_handshake_response(reference.Device, &peer, &response))
        {
            return std::nullopt;
        }
        wireguard_start_session(&peer, true);
        std::vector<std::uint8_t> confirmation = Encrypt(peerId, {});
        return ReceivedPacket{.Peer = peerId,
                              .Plaintext = {},
                              .Reply = std::move(confirmation),
                              .SessionEstablished = true};
    }
    if (type == MESSAGE_COOKIE_REPLY && packet.size() == sizeof(message_cookie_reply))
    {
        message_cookie_reply reply{};
        std::memcpy(&reply, packet.data(), sizeof(reply));
        if (wireguard_process_cookie_message(reference.Device, &peer, &reply))
        {
            peer.send_handshake = true;
        }
        return std::nullopt;
    }
    if (type != MESSAGE_TRANSPORT_DATA ||
        packet.size() < sizeof(message_transport_data) + WIREGUARD_AUTHTAG_LEN)
    {
        return std::nullopt;
    }

    const auto* header = reinterpret_cast<const message_transport_data*>(packet.data());
    wireguard_keypair* keypair = get_peer_keypair_for_idx(&peer, header->receiver);
    if (keypair == nullptr || !keypair->receiving_valid ||
        wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME))
    {
        return std::nullopt;
    }
    const std::uint64_t counter = ReadCounter(header->counter);
    const std::size_t encryptedLength = packet.size() - sizeof(message_transport_data);
    std::vector<std::uint8_t> plaintext(encryptedLength - WIREGUARD_AUTHTAG_LEN);
    if (!DecryptTransport(
            plaintext.data(), header->enc_packet, encryptedLength, counter, *keypair) ||
        !reference.ReplayFor(*keypair).Accept(counter))
    {
        return std::nullopt;
    }

    const bool confirmsResponderSession = keypair == &peer.next_keypair;
    const std::uint32_t now = wireguard_sys_now();
    keypair->last_rx = now;
    peer.last_rx = now;
    keypair_update(&peer, keypair);
    if (confirmsResponderSession)
    {
        Log(LogLevel::Debug,
            "wireguard",
            std::format(
                "responder session confirmed receiver={} counter={}", header->receiver, counter));
    }
    if (keypair->initiator &&
        wireguard_expired(keypair->keypair_millis,
                          REJECT_AFTER_TIME - peer.keepalive_interval - REKEY_TIMEOUT))
    {
        peer.send_handshake = true;
    }

    std::size_t innerLength = plaintext.size();
    if (plaintext.size() >= Ipv4MinimumHeaderSize && (plaintext[0] >> 4) == Ipv4Version)
    {
        innerLength = (static_cast<std::size_t>(plaintext[2]) << 8) | plaintext[3];
    }
    else if (plaintext.size() >= Ipv6MinimumHeaderSize && (plaintext[0] >> 4) == Ipv6Version)
    {
        innerLength =
            Ipv6HeaderSize + ((static_cast<std::size_t>(plaintext[4]) << 8) | plaintext[5]);
    }
    if (innerLength > plaintext.size())
    {
        return std::nullopt;
    }
    plaintext.resize(innerLength);
    return ReceivedPacket{.Peer = peerId,
                          .Plaintext = std::move(plaintext),
                          .Reply = {},
                          .SessionEstablished = false};
}

std::optional<WireGuardTunnel::ReceivedPacket>
WireGuardTunnel::ProcessPacket(const std::vector<std::uint8_t>& packet)
{
    const std::uint8_t type = wireguard_get_message_type(packet.data(), packet.size());
    if (type == MESSAGE_HANDSHAKE_INITIATION &&
        packet.size() == sizeof(message_handshake_initiation))
    {
        message_handshake_initiation initiation{};
        std::memcpy(&initiation, packet.data(), sizeof(initiation));
        for (const std::unique_ptr<wireguard_device>& device : Implementation->Devices)
        {
            wireguard_peer* peer = wireguard_process_initiation_message(device.get(), &initiation);
            if (peer == nullptr)
            {
                continue;
            }
            const auto reference =
                std::find_if(Implementation->Peers.begin(),
                             Implementation->Peers.end(),
                             [&](const Impl::PeerReference& candidate)
                             {
                                 return candidate.Device == device.get() && candidate.Peer == peer;
                             });
            if (reference == Implementation->Peers.end())
            {
                return std::nullopt;
            }
            message_handshake_response response{};
            if (!wireguard_create_handshake_response(device.get(), peer, &response))
            {
                return std::nullopt;
            }
            wireguard_start_session(peer, false);
            return ReceivedPacket{
                .Peer = static_cast<PeerId>(reference - Implementation->Peers.begin()),
                .Plaintext = {},
                .Reply = {reinterpret_cast<const std::uint8_t*>(&response),
                          reinterpret_cast<const std::uint8_t*>(&response) + sizeof(response)},
                .SessionEstablished = true};
        }
        return std::nullopt;
    }
    for (PeerId peer = 0; peer < Implementation->Peers.size(); ++peer)
    {
        if (std::optional<ReceivedPacket> received = ProcessPacket(peer, packet))
        {
            return received;
        }
    }
    return std::nullopt;
}

std::vector<std::uint8_t> WireGuardTunnel::Encrypt(PeerId peerId,
                                                   const std::vector<std::uint8_t>& plaintext)
{
    wireguard_peer& peer = *Implementation->GetPeer(peerId).Peer;
    wireguard_keypair* keypair = FindSendingKeypair(peer);
    if (keypair == nullptr)
    {
        throw std::runtime_error("WireGuard peer has no usable session.");
    }

    const std::size_t paddedLength =
        (plaintext.size() + WireGuardPaddingAlignment - 1U) & ~(WireGuardPaddingAlignment - 1U);
    std::vector<std::uint8_t> packet(
        sizeof(message_transport_data) + paddedLength + WIREGUARD_AUTHTAG_LEN, 0);
    auto* header = reinterpret_cast<message_transport_data*>(packet.data());
    header->type = MESSAGE_TRANSPORT_DATA;
    header->receiver = keypair->remote_index;
    WriteCounter(header->counter, keypair->sending_counter);
    std::vector<std::uint8_t> padded(paddedLength, 0);
    std::copy(plaintext.begin(), plaintext.end(), padded.begin());
    EncryptTransport(header->enc_packet, padded.data(), padded.size(), *keypair);

    const std::uint32_t now = wireguard_sys_now();
    keypair->last_tx = now;
    peer.last_tx = now;
    if (keypair->sending_counter >= REKEY_AFTER_MESSAGES ||
        (keypair->initiator && wireguard_expired(keypair->keypair_millis, REKEY_AFTER_TIME)))
    {
        peer.send_handshake = true;
    }
    return packet;
}

WireGuardTunnel::TimerAction WireGuardTunnel::UpdateTimers(PeerId peerId)
{
    wireguard_peer& peer = *Implementation->GetPeer(peerId).Peer;
    if (peer.curr_keypair.valid &&
        (wireguard_expired(peer.curr_keypair.keypair_millis, REJECT_AFTER_TIME) ||
         peer.curr_keypair.sending_counter >= REJECT_AFTER_MESSAGES))
    {
        keypair_destroy(&peer.curr_keypair);
    }
    const bool hasUsableSession = FindSendingKeypair(peer) != nullptr;
    const bool handshakeNeeded = peer.send_handshake || (!hasUsableSession && peer.active) ||
                                 (peer.curr_keypair.valid && !peer.curr_keypair.initiator &&
                                  wireguard_expired(peer.curr_keypair.keypair_millis,
                                                    REJECT_AFTER_TIME - peer.keepalive_interval));
    const bool initiationAllowed =
        peer.last_initiation_tx == 0 || wireguard_expired(peer.last_initiation_tx, REKEY_TIMEOUT);
    if (handshakeNeeded && initiationAllowed)
    {
        return TimerAction::SendHandshake;
    }
    if (peer.keepalive_interval > 0 && hasUsableSession &&
        wireguard_expired(peer.last_tx, peer.keepalive_interval))
    {
        return TimerAction::SendKeepalive;
    }
    return TimerAction::None;
}

bool WireGuardTunnel::HasSession(PeerId peerId) const
{
    const wireguard_peer& peer = *Implementation->GetPeer(peerId).Peer;
    return FindSendingKeypair(peer) != nullptr;
}

} // namespace tailgate::wgengine::wireguard
