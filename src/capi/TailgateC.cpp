#include "tailgate/c/tailgate.h"

#include "tailgate/ByteStream.h"
#include "tailgate/Logging.h"
#include "tailgate/control/ControlClient.h"
#include "tailgate/network/Ipv4.h"
#include "tailgate/protocol/DerpClient.h"
#include "tailgate/protocol/Disco.h"
#include "tailgate/protocol/WireGuardTunnel.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{

thread_local std::string LastError;

class CallbackStream final : public tailgate::IByteStream
{
public:
    explicit CallbackStream(tg_stream stream) : Stream(stream)
    {
        if (Stream.try_write_some == nullptr || Stream.try_read_some == nullptr)
        {
            throw std::invalid_argument("stream callbacks are required");
        }
    }

    std::optional<std::size_t> TryWriteSome(const std::uint8_t* data, std::size_t size) override
    {
        std::size_t written = 0;
        const tg_stream_result result = Stream.try_write_some(Stream.context, data, size, &written);
        if (result == TG_STREAM_WOULD_BLOCK)
        {
            return std::nullopt;
        }
        if (result != TG_STREAM_READY || written > size)
        {
            throw std::runtime_error("stream write failed");
        }
        return written;
    }

    std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t maxBytes) override
    {
        std::vector<std::uint8_t> result(maxBytes);
        std::size_t size = 0;
        const tg_stream_result streamResult =
            Stream.try_read_some(Stream.context, result.data(), result.size(), &size);
        if (streamResult == TG_STREAM_WOULD_BLOCK)
        {
            return std::nullopt;
        }
        if (streamResult != TG_STREAM_READY || size > result.size())
        {
            throw std::runtime_error("stream read failed");
        }
        result.resize(size);
        return result;
    }

private:
    tg_stream Stream;
};

tg_buffer CopyBuffer(const std::vector<std::uint8_t>& source)
{
    tg_buffer result{};
    if (source.empty())
    {
        return result;
    }
    result.data = static_cast<std::uint8_t*>(std::malloc(source.size()));
    if (result.data == nullptr)
    {
        throw std::bad_alloc();
    }
    std::memcpy(result.data, source.data(), source.size());
    result.size = source.size();
    return result;
}

template <typename Function>
int Guard(Function function)
{
    try
    {
        function();
        LastError.clear();
        return 0;
    }
    catch (const std::exception& error)
    {
        LastError = error.what();
        return -1;
    }
}

tailgate::protocol::WireGuardTunnel::Key Key(const std::uint8_t* source)
{
    tailgate::protocol::WireGuardTunnel::Key result{};
    if (source != nullptr)
    {
        std::copy_n(source, result.size(), result.begin());
    }
    return result;
}

} // namespace

struct tg_control
{
    CallbackStream Stream;
    tailgate::control::ControlClient Client;

    tg_control(tg_stream stream,
               const tailgate::protocol::Bytes32& machineKey,
               const tailgate::protocol::Bytes32& nodeKey,
               const tailgate::protocol::HostInfo& host)
        : Stream(stream), Client(Stream, machineKey, nodeKey, host)
    {
    }
};

struct tg_tunnel
{
    explicit tg_tunnel(const tailgate::protocol::WireGuardTunnel::Key& key) : Tunnel(key)
    {
    }
    tailgate::protocol::WireGuardTunnel Tunnel;
};

struct tg_network_config
{
    tailgate::control::NetworkConfig Config;
};

struct tg_derp
{
    CallbackStream Stream;
    tailgate::protocol::DerpClient Client;

    tg_derp(tg_stream stream,
            const tailgate::protocol::Bytes32& privateKey,
            const tailgate::protocol::Bytes32& publicKey)
        : Stream(stream), Client(Stream, privateKey, publicKey)
    {
    }
};

struct tg_disco
{
    tg_disco(const tailgate::protocol::Bytes32& privateKey,
             const tailgate::protocol::Bytes32& nodePublicKey)
        : Client(privateKey, nodePublicKey)
    {
    }
    tailgate::protocol::Disco Client;
};

extern "C"
{

    const char* tg_last_error(void)
    {
        return LastError.c_str();
    }
    void tg_buffer_free(tg_buffer buffer)
    {
        std::free(buffer.data);
    }

    void tg_set_log_callback(void* context, tg_log_callback callback)
    {
        if (callback == nullptr)
        {
            tailgate::SetLogSink({});
            return;
        }
        tailgate::SetLogSink(
            [context, callback](
                tailgate::LogLevel level, const std::string& component, const std::string& message)
            {
                callback(
                    context, static_cast<tg_log_level>(level), component.c_str(), message.c_str());
            });
    }

    uint16_t tg_internet_checksum(const uint8_t* data, size_t size)
    {
        return data == nullptr && size != 0 ? 0 : tailgate::network::InternetChecksum(data, size);
    }

    int tg_generate_private_key(uint8_t private_key[32])
    {
        return Guard(
            [&]()
            {
                if (private_key == nullptr)
                    throw std::invalid_argument("private key is required");
                const auto key = tailgate::protocol::GeneratePrivateKey();
                std::copy(key.begin(), key.end(), private_key);
            });
    }

    int
    tg_ipv4_destination(const uint8_t* packet, size_t packet_size, uint32_t* destination_host_order)
    {
        return Guard(
            [&]()
            {
                if (packet == nullptr || destination_host_order == nullptr)
                    throw std::invalid_argument("packet arguments are required");
                const auto destination = tailgate::network::Ipv4Destination(
                    std::vector<std::uint8_t>(packet, packet + packet_size));
                if (!destination)
                    throw std::runtime_error("packet is not IPv4");
                *destination_host_order = *destination;
            });
    }

    tg_control* tg_control_create(tg_stream stream,
                                  const uint8_t machine_private_key[32],
                                  const uint8_t node_private_key[32],
                                  const tg_host_info* host)
    {
        try
        {
            if (machine_private_key == nullptr || node_private_key == nullptr || host == nullptr)
            {
                throw std::invalid_argument("control arguments are required");
            }
            tailgate::protocol::Bytes32 machine{};
            tailgate::protocol::Bytes32 node{};
            std::copy_n(machine_private_key, machine.size(), machine.begin());
            std::copy_n(node_private_key, node.size(), node.begin());
            tailgate::protocol::HostInfo info{
                host->hostname == nullptr ? "" : host->hostname,
                host->operating_system == nullptr ? "" : host->operating_system,
                host->operating_system_version == nullptr ? "" : host->operating_system_version,
                host->architecture == nullptr ? "" : host->architecture,
                host->client_version == nullptr ? "Tailgate" : host->client_version};
            return new tg_control(stream, machine, node, info);
        }
        catch (const std::exception& error)
        {
            LastError = error.what();
            return nullptr;
        }
    }

    void tg_control_destroy(tg_control* control)
    {
        delete control;
    }

    int tg_control_register(tg_control* control, const char* auth_key, tg_buffer* output)
    {
        return Guard(
            [&]()
            {
                if (control == nullptr || auth_key == nullptr || output == nullptr)
                {
                    throw std::invalid_argument("control register arguments are required");
                }
                const tailgate::control::NetworkConfig config =
                    control->Client.RegisterAndGetNetworkMap(auth_key);
                nlohmann::json peers = nlohmann::json::array();
                for (const auto& peer : config.Peers)
                {
                    peers.push_back({{"Name", peer.Name},
                                     {"Address", peer.Address},
                                     {"Key", peer.Key},
                                     {"DiscoKey", peer.DiscoKey},
                                     {"Endpoints", peer.Endpoints},
                                     {"DERPRegion", peer.DerpRegion},
                                     {"DERPCode", peer.DerpCode},
                                     {"DERPHost", peer.DerpHost},
                                     {"OS", peer.OperatingSystem},
                                     {"Online", peer.Online},
                                     {"ExitNodeOption", peer.ExitNodeOption}});
                }
                const std::string json = nlohmann::json({{"SelfAddress", config.SelfAddress},
                                                         {"DNSResolver", config.DnsResolver},
                                                         {"DNSDomains", config.DnsDomains},
                                                         {"DERPRegion", config.DerpRegion},
                                                         {"DERPHost", config.DerpHost},
                                                         {"DERPCode", config.DerpCode},
                                                         {"Peers", std::move(peers)}})
                                             .dump();
                *output = CopyBuffer(std::vector<std::uint8_t>(json.begin(), json.end()));
            });
    }

    int tg_control_register_network(tg_control* control,
                                    const char* auth_key,
                                    tg_network_config** network_config)
    {
        return Guard(
            [&]()
            {
                if (control == nullptr || auth_key == nullptr || network_config == nullptr)
                    throw std::invalid_argument("control register arguments are required");
                auto result = std::make_unique<tg_network_config>();
                result->Config = control->Client.RegisterAndGetNetworkMap(auth_key);
                *network_config = result.release();
            });
    }

    int tg_control_set_preferred_derp(tg_control* control, int region)
    {
        return Guard(
            [&]()
            {
                if (control == nullptr)
                    throw std::invalid_argument("control is required");
                control->Client.SetPreferredDerp(region);
            });
    }

    int tg_control_poll_network(tg_control* control, tg_network_config** networkConfig)
    {
        if (control == nullptr || networkConfig == nullptr)
        {
            LastError = "control poll arguments are required";
            return -1;
        }
        try
        {
            std::optional<tailgate::control::NetworkConfig> update =
                control->Client.PollNetworkMap();
            if (!update)
            {
                *networkConfig = nullptr;
                LastError.clear();
                return 1;
            }
            auto result = std::make_unique<tg_network_config>();
            result->Config = std::move(*update);
            *networkConfig = result.release();
            LastError.clear();
            return 0;
        }
        catch (const std::exception& error)
        {
            LastError = error.what();
            return -1;
        }
    }

    int tg_control_logout(tg_control* control)
    {
        return Guard(
            [&]()
            {
                if (control == nullptr)
                    throw std::invalid_argument("control is required");
                control->Client.Logout();
            });
    }

    int tg_control_node_public_key(const tg_control* control, uint8_t public_key[32])
    {
        return Guard(
            [&]()
            {
                if (control == nullptr || public_key == nullptr)
                    throw std::invalid_argument("control arguments are required");
                const auto& key = control->Client.NodePublicKey();
                std::copy(key.begin(), key.end(), public_key);
            });
    }

    int tg_control_disco_private_key(const tg_control* control, uint8_t private_key[32])
    {
        return Guard(
            [&]()
            {
                if (control == nullptr || private_key == nullptr)
                    throw std::invalid_argument("control arguments are required");
                const auto& key = control->Client.DiscoPrivateKey();
                std::copy(key.begin(), key.end(), private_key);
            });
    }

    void tg_network_config_destroy(tg_network_config* config)
    {
        delete config;
    }

    const char* tg_network_self_address(const tg_network_config* config)
    {
        return config == nullptr ? nullptr : config->Config.SelfAddress.c_str();
    }

    const char* tg_network_dns_resolver(const tg_network_config* config)
    {
        return config == nullptr ? nullptr : config->Config.DnsResolver.c_str();
    }

    size_t tg_network_dns_domain_count(const tg_network_config* config)
    {
        return config == nullptr ? 0 : config->Config.DnsDomains.size();
    }

    const char* tg_network_dns_domain(const tg_network_config* config, size_t index)
    {
        return config == nullptr || index >= config->Config.DnsDomains.size()
                   ? nullptr
                   : config->Config.DnsDomains[index].c_str();
    }

    int tg_network_derp_region(const tg_network_config* config)
    {
        return config == nullptr ? 0 : config->Config.DerpRegion;
    }

    const char* tg_network_derp_host(const tg_network_config* config)
    {
        return config == nullptr ? nullptr : config->Config.DerpHost.c_str();
    }

    const char* tg_network_derp_code(const tg_network_config* config, int region)
    {
        if (config == nullptr)
        {
            return nullptr;
        }
        thread_local std::string code;
        code = tailgate::control::DerpCode(config->Config, region);
        return code.c_str();
    }

    size_t tg_network_peer_count(const tg_network_config* config)
    {
        return config == nullptr ? 0 : config->Config.Peers.size();
    }

    int tg_network_peer(const tg_network_config* config, size_t index, tg_peer_info* peer)
    {
        return Guard(
            [&]()
            {
                if (config == nullptr || peer == nullptr || index >= config->Config.Peers.size())
                    throw std::invalid_argument("peer index is invalid");
                const auto& source = config->Config.Peers[index];
                *peer = {source.Name.c_str(),
                         source.Address.c_str(),
                         source.Key.c_str(),
                         source.DiscoKey.c_str(),
                         source.OperatingSystem.c_str(),
                         source.DerpRegion,
                         source.DerpCode.c_str(),
                         source.DerpHost.c_str(),
                         source.Online ? 1 : 0,
                         source.ExitNodeOption ? 1 : 0};
            });
    }

    int
    tg_network_peer_node_key(const tg_network_config* config, size_t index, uint8_t node_key[32])
    {
        return Guard(
            [&]()
            {
                if (config == nullptr || node_key == nullptr ||
                    index >= config->Config.Peers.size())
                    throw std::invalid_argument("peer index is invalid");
                const auto& text = config->Config.Peers[index].Key;
                if (text.rfind("nodekey:", 0) != 0)
                    throw std::runtime_error("peer has no node key");
                const auto key = tailgate::protocol::HexToBytes(text.substr(8));
                if (key.size() != 32)
                    throw std::runtime_error("peer node key is invalid");
                std::copy(key.begin(), key.end(), node_key);
            });
    }

    int
    tg_network_peer_disco_key(const tg_network_config* config, size_t index, uint8_t disco_key[32])
    {
        return Guard(
            [&]()
            {
                if (config == nullptr || disco_key == nullptr ||
                    index >= config->Config.Peers.size())
                    throw std::invalid_argument("peer index is invalid");
                const auto& text = config->Config.Peers[index].DiscoKey;
                if (text.rfind("discokey:", 0) != 0)
                    throw std::runtime_error("peer has no disco key");
                const auto key = tailgate::protocol::HexToBytes(text.substr(9));
                if (key.size() != 32)
                    throw std::runtime_error("peer disco key is invalid");
                std::copy(key.begin(), key.end(), disco_key);
            });
    }

    size_t tg_network_peer_endpoint_count(const tg_network_config* config, size_t peerIndex)
    {
        return config == nullptr || peerIndex >= config->Config.Peers.size()
                   ? 0
                   : config->Config.Peers[peerIndex].Endpoints.size();
    }

    const char* tg_network_peer_endpoint(const tg_network_config* config,
                                         size_t peerIndex,
                                         size_t endpointIndex)
    {
        if (config == nullptr || peerIndex >= config->Config.Peers.size() ||
            endpointIndex >= config->Config.Peers[peerIndex].Endpoints.size())
            return nullptr;
        return config->Config.Peers[peerIndex].Endpoints[endpointIndex].c_str();
    }

    int tg_network_find_peer_ipv4(const tg_network_config* config,
                                  uint32_t destination,
                                  size_t* peerIndex)
    {
        if (config == nullptr || peerIndex == nullptr)
            return -1;
        const auto found = tailgate::control::FindRoute(config->Config.Peers, destination);
        if (!found)
            return 1;
        *peerIndex = *found;
        return 0;
    }

    int tg_network_find_route_ipv4(const tg_network_config* config,
                                   const tg_preferences* preferences,
                                   uint32_t destination,
                                   size_t* peerIndex)
    {
        if (config == nullptr || preferences == nullptr || peerIndex == nullptr)
            return -1;
        std::optional<std::size_t> exitNode;
        if (preferences->exit_node != nullptr && preferences->exit_node[0] != '\0')
        {
            exitNode =
                tailgate::control::FindExitNode(config->Config.Peers, preferences->exit_node);
            if (!exitNode)
            {
                LastError = "requested exit node is unavailable";
                return -1;
            }
        }
        const auto routed =
            tailgate::control::FindRoute(config->Config.Peers, destination, exitNode);
        if (routed)
        {
            *peerIndex = *routed;
            return 0;
        }
        return 1;
    }

    int tg_network_find_exit_node(const tg_network_config* config,
                                  const char* nameOrAddress,
                                  size_t* peerIndex)
    {
        return Guard(
            [&]()
            {
                if (config == nullptr || nameOrAddress == nullptr || peerIndex == nullptr)
                    throw std::invalid_argument("exit-node lookup arguments are required");
                const auto found =
                    tailgate::control::FindExitNode(config->Config.Peers, nameOrAddress);
                if (!found)
                    throw std::runtime_error("requested exit node is unavailable");
                *peerIndex = *found;
            });
    }

    tg_derp* tg_derp_create(tg_stream stream,
                            const uint8_t node_private_key[32],
                            const uint8_t node_public_key[32])
    {
        try
        {
            return new tg_derp(stream, Key(node_private_key), Key(node_public_key));
        }
        catch (const std::exception& error)
        {
            LastError = error.what();
            return nullptr;
        }
    }

    void tg_derp_destroy(tg_derp* derp)
    {
        delete derp;
    }

    int tg_derp_connect(tg_derp* derp, const char* hostname)
    {
        return Guard(
            [&]()
            {
                if (derp == nullptr || hostname == nullptr)
                    throw std::invalid_argument("DERP connect arguments are required");
                derp->Client.Connect(hostname);
            });
    }

    int tg_derp_set_preferred(tg_derp* derp, int preferred)
    {
        return Guard(
            [&]()
            {
                if (derp == nullptr)
                    throw std::invalid_argument("DERP client is required");
                derp->Client.SetPreferred(preferred != 0);
            });
    }

    int tg_derp_send(tg_derp* derp,
                     const uint8_t destination_node_key[32],
                     const uint8_t* packet,
                     size_t packet_size)
    {
        return Guard(
            [&]()
            {
                if (derp == nullptr || destination_node_key == nullptr ||
                    (packet == nullptr && packet_size != 0))
                    throw std::invalid_argument("DERP send arguments are required");
                const std::vector<std::uint8_t> data =
                    packet_size == 0 ? std::vector<std::uint8_t>{}
                                     : std::vector<std::uint8_t>(packet, packet + packet_size);
                derp->Client.Send(Key(destination_node_key), data);
            });
    }

    int tg_derp_receive(tg_derp* derp, uint8_t source_node_key[32], tg_buffer* packet)
    {
        return Guard(
            [&]()
            {
                if (derp == nullptr || source_node_key == nullptr || packet == nullptr)
                    throw std::invalid_argument("DERP receive arguments are required");
                const auto received = derp->Client.Receive();
                std::copy(received.Source.begin(), received.Source.end(), source_node_key);
                *packet = CopyBuffer(received.Payload);
            });
    }

    int tg_derp_receive_available(tg_derp* derp, uint8_t sourceNodeKey[32], tg_buffer* packet)
    {
        if (derp == nullptr || sourceNodeKey == nullptr || packet == nullptr)
        {
            LastError = "DERP receive arguments are required";
            return -1;
        }
        try
        {
            const auto received = derp->Client.ReceiveAvailable();
            if (!received)
            {
                *packet = {};
                LastError.clear();
                return 1;
            }
            std::copy(received->Source.begin(), received->Source.end(), sourceNodeKey);
            *packet = CopyBuffer(received->Payload);
            LastError.clear();
            return 0;
        }
        catch (const std::exception& error)
        {
            LastError = error.what();
            return -1;
        }
    }

    int tg_derp_flush(tg_derp* derp)
    {
        return Guard(
            [&]()
            {
                if (derp == nullptr)
                    throw std::invalid_argument("DERP client is required");
                derp->Client.Flush();
            });
    }

    int tg_derp_has_pending_output(const tg_derp* derp)
    {
        return derp != nullptr && derp->Client.HasPendingOutput() ? 1 : 0;
    }

    tg_disco* tg_disco_create(const uint8_t disco_private_key[32],
                              const uint8_t node_public_key[32])
    {
        try
        {
            return new tg_disco(Key(disco_private_key), Key(node_public_key));
        }
        catch (const std::exception& error)
        {
            LastError = error.what();
            return nullptr;
        }
    }

    void tg_disco_destroy(tg_disco* disco)
    {
        delete disco;
    }

    int tg_disco_public_key(const tg_disco* disco, uint8_t public_key[32])
    {
        return Guard(
            [&]()
            {
                if (disco == nullptr || public_key == nullptr)
                    throw std::invalid_argument("disco arguments are required");
                const auto& key = disco->Client.PublicKey();
                std::copy(key.begin(), key.end(), public_key);
            });
    }

    int tg_disco_new_transaction(const tg_disco* disco, uint8_t transaction_id[12])
    {
        return Guard(
            [&]()
            {
                if (disco == nullptr || transaction_id == nullptr)
                    throw std::invalid_argument("disco arguments are required");
                const auto transaction = disco->Client.NewTransactionId();
                std::copy(transaction.begin(), transaction.end(), transaction_id);
            });
    }

    int tg_disco_build_ping(const tg_disco* disco,
                            const uint8_t recipient_disco_key[32],
                            const uint8_t transaction_id[12],
                            tg_buffer* packet)
    {
        return Guard(
            [&]()
            {
                if (disco == nullptr || recipient_disco_key == nullptr ||
                    transaction_id == nullptr || packet == nullptr)
                    throw std::invalid_argument("disco ping arguments are required");
                tailgate::protocol::Disco::TransactionId transaction{};
                std::copy_n(transaction_id, transaction.size(), transaction.begin());
                *packet =
                    CopyBuffer(disco->Client.BuildPing(Key(recipient_disco_key), transaction));
            });
    }

    int tg_disco_build_pong(const tg_disco* disco,
                            const uint8_t recipient_disco_key[32],
                            const uint8_t transaction_id[12],
                            uint32_t source_address_host_order,
                            uint16_t source_port,
                            tg_buffer* packet)
    {
        return Guard(
            [&]()
            {
                if (disco == nullptr || recipient_disco_key == nullptr ||
                    transaction_id == nullptr || packet == nullptr)
                    throw std::invalid_argument("disco pong arguments are required");
                tailgate::protocol::Disco::TransactionId transaction{};
                std::copy_n(transaction_id, transaction.size(), transaction.begin());
                *packet = CopyBuffer(disco->Client.BuildPong(
                    Key(recipient_disco_key), transaction, source_address_host_order, source_port));
            });
    }

    int tg_disco_build_call_me_maybe(const tg_disco* disco,
                                     const uint8_t recipient_discco_key[32],
                                     const uint32_t* endpoint_addresses_host_order,
                                     const uint16_t* endpoint_ports,
                                     size_t endpoint_count,
                                     tg_buffer* packet)
    {
        return Guard(
            [&]()
            {
                if (disco == nullptr || recipient_discco_key == nullptr ||
                    endpoint_addresses_host_order == nullptr || endpoint_ports == nullptr ||
                    packet == nullptr)
                    throw std::invalid_argument("disco CallMeMaybe arguments are required");
                std::vector<tailgate::protocol::Disco::Endpoint> endpoints;
                endpoints.reserve(endpoint_count);
                for (std::size_t index = 0; index < endpoint_count; ++index)
                {
                    endpoints.push_back(
                        {endpoint_addresses_host_order[index], endpoint_ports[index]});
                }
                *packet = CopyBuffer(
                    disco->Client.BuildCallMeMaybe(Key(recipient_discco_key), endpoints));
            });
    }

    int tg_disco_parse(const tg_disco* disco,
                       const uint8_t* packet,
                       size_t packet_size,
                       tg_disco_message* message)
    {
        return Guard(
            [&]()
            {
                if (disco == nullptr || packet == nullptr || message == nullptr)
                    throw std::invalid_argument("disco parse arguments are required");
                const auto parsed =
                    disco->Client.Parse(std::vector<std::uint8_t>(packet, packet + packet_size));
                if (!parsed)
                    throw std::runtime_error("packet is not a valid disco message");
                message->type = parsed->Type == tailgate::protocol::Disco::MessageType::Ping
                                    ? TG_DISCO_PING
                                : parsed->Type == tailgate::protocol::Disco::MessageType::Pong
                                    ? TG_DISCO_PONG
                                    : TG_DISCO_CALL_ME_MAYBE;
                std::copy(parsed->Sender.begin(), parsed->Sender.end(), message->sender);
                std::copy(parsed->Transaction.begin(),
                          parsed->Transaction.end(),
                          message->transaction_id);
                message->endpoint_count = std::min(parsed->Endpoints.size(), std::size_t{8});
                for (std::size_t index = 0; index < message->endpoint_count; ++index)
                {
                    message->endpoint_addresses[index] = parsed->Endpoints[index].Address;
                    message->endpoint_ports[index] = parsed->Endpoints[index].Port;
                }
            });
    }

    tg_tunnel* tg_tunnel_create(const uint8_t private_key[32])
    {
        try
        {
            return new tg_tunnel(Key(private_key));
        }
        catch (const std::exception& error)
        {
            LastError = error.what();
            return nullptr;
        }
    }
    void tg_tunnel_destroy(tg_tunnel* tunnel)
    {
        delete tunnel;
    }

    int tg_tunnel_add_peer(tg_tunnel* tunnel,
                           const uint8_t public_key[32],
                           const uint8_t preshared_key[32],
                           uint16_t keepalive,
                           size_t* peer_id)
    {
        return Guard(
            [&]()
            {
                if (tunnel == nullptr || public_key == nullptr || peer_id == nullptr)
                    throw std::invalid_argument("peer arguments are required");
                *peer_id = tunnel->Tunnel.AddPeer(Key(public_key), Key(preshared_key), keepalive);
            });
    }

    int tg_tunnel_create_handshake(tg_tunnel* tunnel, size_t peer_id, tg_buffer* packet)
    {
        return Guard(
            [&]()
            {
                *packet = CopyBuffer(tunnel->Tunnel.CreateHandshake(peer_id));
            });
    }

    int tg_tunnel_process_packet(tg_tunnel* tunnel,
                                 size_t peer_id,
                                 const uint8_t* packet,
                                 size_t packet_size,
                                 tg_received_packet* result)
    {
        return Guard(
            [&]()
            {
                if (tunnel == nullptr || packet == nullptr || result == nullptr)
                    throw std::invalid_argument("packet arguments are required");
                *result = {};
                const auto received = tunnel->Tunnel.ProcessPacket(
                    peer_id, std::vector<std::uint8_t>(packet, packet + packet_size));
                if (received)
                {
                    result->plaintext = CopyBuffer(received->Plaintext);
                    result->reply = CopyBuffer(received->Reply);
                    result->session_established = received->SessionEstablished ? 1 : 0;
                }
            });
    }

    int tg_tunnel_encrypt(tg_tunnel* tunnel,
                          size_t peer_id,
                          const uint8_t* plaintext,
                          size_t plaintext_size,
                          tg_buffer* packet)
    {
        return Guard(
            [&]()
            {
                if (tunnel == nullptr || packet == nullptr ||
                    (plaintext == nullptr && plaintext_size != 0))
                    throw std::invalid_argument("encrypt arguments are required");
                const std::vector<std::uint8_t> input =
                    plaintext_size == 0
                        ? std::vector<std::uint8_t>{}
                        : std::vector<std::uint8_t>(plaintext, plaintext + plaintext_size);
                *packet = CopyBuffer(tunnel->Tunnel.Encrypt(peer_id, input));
            });
    }

    int tg_tunnel_has_session(tg_tunnel* tunnel, size_t peer_id)
    {
        if (tunnel == nullptr)
            return 0;
        try
        {
            return tunnel->Tunnel.HasSession(peer_id) ? 1 : 0;
        }
        catch (const std::exception& error)
        {
            LastError = error.what();
            return 0;
        }
    }

    int tg_tunnel_update_timers(tg_tunnel* tunnel, size_t peer_id, tg_tunnel_action* action)
    {
        return Guard(
            [&]()
            {
                if (tunnel == nullptr || action == nullptr)
                    throw std::invalid_argument("tunnel timer arguments are required");
                *action = static_cast<tg_tunnel_action>(tunnel->Tunnel.UpdateTimers(peer_id));
            });
    }

} // extern "C"
