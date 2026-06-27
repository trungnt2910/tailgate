#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct tg_control tg_control;
    typedef struct tg_tunnel tg_tunnel;
    typedef struct tg_network_config tg_network_config;
    typedef struct tg_derp tg_derp;
    typedef struct tg_disco tg_disco;

    typedef struct tg_buffer
    {
        uint8_t* data;
        size_t size;
    } tg_buffer;

    typedef enum tg_stream_result
    {
        TG_STREAM_ERROR = -1,
        TG_STREAM_READY = 0,
        TG_STREAM_WOULD_BLOCK = 1
    } tg_stream_result;

    typedef struct tg_stream
    {
        void* context;
        tg_stream_result (*try_write_some)(void* context,
                                           const uint8_t* data,
                                           size_t size,
                                           size_t* written);
        tg_stream_result (*try_read_some)(void* context,
                                          uint8_t* data,
                                          size_t capacity,
                                          size_t* read);
    } tg_stream;

    typedef struct tg_host_info
    {
        const char* hostname;
        const char* operating_system;
        const char* operating_system_version;
        const char* architecture;
        const char* client_version;
    } tg_host_info;

    typedef struct tg_preferences
    {
        const char* hostname;
        const char* exit_node;
        int accept_dns;
    } tg_preferences;

    typedef enum tg_log_level
    {
        TG_LOG_TRACE,
        TG_LOG_DEBUG,
        TG_LOG_INFO,
        TG_LOG_WARNING,
        TG_LOG_ERROR
    } tg_log_level;

    typedef void (*tg_log_callback)(void* context,
                                    tg_log_level level,
                                    const char* component,
                                    const char* message);

    typedef struct tg_received_packet
    {
        tg_buffer plaintext;
        tg_buffer reply;
        int session_established;
    } tg_received_packet;

    typedef struct tg_peer_info
    {
        const char* name;
        const char* address;
        const char* node_key;
        const char* disco_key;
        const char* operating_system;
        int derp_region;
        const char* derp_code;
        const char* derp_host;
        int online;
        int offers_exit_node;
    } tg_peer_info;

    typedef enum tg_tunnel_action
    {
        TG_TUNNEL_ACTION_NONE,
        TG_TUNNEL_ACTION_SEND_HANDSHAKE,
        TG_TUNNEL_ACTION_SEND_KEEPALIVE
    } tg_tunnel_action;

    typedef enum tg_disco_message_type
    {
        TG_DISCO_PING = 1,
        TG_DISCO_PONG = 2,
        TG_DISCO_CALL_ME_MAYBE = 3
    } tg_disco_message_type;

    typedef struct tg_disco_message
    {
        tg_disco_message_type type;
        uint8_t sender[32];
        uint8_t transaction_id[12];
        size_t endpoint_count;
        uint32_t endpoint_addresses[8];
        uint16_t endpoint_ports[8];
    } tg_disco_message;

    const char* tg_last_error(void);
    void tg_buffer_free(tg_buffer buffer);
    void tg_set_log_callback(void* context, tg_log_callback callback);
    uint16_t tg_internet_checksum(const uint8_t* data, size_t size);
    int tg_generate_private_key(uint8_t private_key[32]);
    int tg_ipv4_destination(const uint8_t* packet,
                            size_t packet_size,
                            uint32_t* destination_host_order);

    tg_control* tg_control_create(tg_stream stream,
                                  const uint8_t machine_private_key[32],
                                  const uint8_t node_private_key[32],
                                  const tg_host_info* host);
    void tg_control_destroy(tg_control* control);
    int
    tg_control_register(tg_control* control, const char* auth_key, tg_buffer* network_config_json);
    int tg_control_register_network(tg_control* control,
                                    const char* auth_key,
                                    tg_network_config** network_config);
    int tg_control_set_preferred_derp(tg_control* control, int region);
    int tg_control_poll_network(tg_control* control, tg_network_config** network_config);
    int tg_control_logout(tg_control* control);
    int tg_control_node_public_key(const tg_control* control, uint8_t public_key[32]);
    int tg_control_disco_private_key(const tg_control* control, uint8_t private_key[32]);

    void tg_network_config_destroy(tg_network_config* config);
    const char* tg_network_self_address(const tg_network_config* config);
    const char* tg_network_dns_resolver(const tg_network_config* config);
    size_t tg_network_dns_domain_count(const tg_network_config* config);
    const char* tg_network_dns_domain(const tg_network_config* config, size_t index);
    int tg_network_derp_region(const tg_network_config* config);
    const char* tg_network_derp_host(const tg_network_config* config);
    const char* tg_network_derp_code(const tg_network_config* config, int region);
    size_t tg_network_peer_count(const tg_network_config* config);
    int tg_network_peer(const tg_network_config* config, size_t index, tg_peer_info* peer);
    int
    tg_network_peer_node_key(const tg_network_config* config, size_t index, uint8_t node_key[32]);
    int
    tg_network_peer_disco_key(const tg_network_config* config, size_t index, uint8_t disco_key[32]);
    size_t tg_network_peer_endpoint_count(const tg_network_config* config, size_t peer_index);
    const char* tg_network_peer_endpoint(const tg_network_config* config,
                                         size_t peer_index,
                                         size_t endpoint_index);
    int tg_network_find_peer_ipv4(const tg_network_config* config,
                                  uint32_t destination_host_order,
                                  size_t* peer_index);
    int tg_network_find_route_ipv4(const tg_network_config* config,
                                   const tg_preferences* preferences,
                                   uint32_t destination_host_order,
                                   size_t* peer_index);
    int tg_network_find_exit_node(const tg_network_config* config,
                                  const char* name_or_address,
                                  size_t* peer_index);

    tg_derp* tg_derp_create(tg_stream stream,
                            const uint8_t node_private_key[32],
                            const uint8_t node_public_key[32]);
    void tg_derp_destroy(tg_derp* derp);
    int tg_derp_connect(tg_derp* derp, const char* hostname);
    int tg_derp_set_preferred(tg_derp* derp, int preferred);
    int tg_derp_send(tg_derp* derp,
                     const uint8_t destination_node_key[32],
                     const uint8_t* packet,
                     size_t packet_size);
    int tg_derp_receive(tg_derp* derp, uint8_t source_node_key[32], tg_buffer* packet);
    int tg_derp_receive_available(tg_derp* derp, uint8_t source_node_key[32], tg_buffer* packet);
    int tg_derp_flush(tg_derp* derp);
    int tg_derp_has_pending_output(const tg_derp* derp);

    tg_disco* tg_disco_create(const uint8_t disco_private_key[32],
                              const uint8_t node_public_key[32]);
    void tg_disco_destroy(tg_disco* disco);
    int tg_disco_public_key(const tg_disco* disco, uint8_t public_key[32]);
    int tg_disco_new_transaction(const tg_disco* disco, uint8_t transaction_id[12]);
    int tg_disco_build_ping(const tg_disco* disco,
                            const uint8_t recipient_disco_key[32],
                            const uint8_t transaction_id[12],
                            tg_buffer* packet);
    int tg_disco_build_pong(const tg_disco* disco,
                            const uint8_t recipient_disco_key[32],
                            const uint8_t transaction_id[12],
                            uint32_t source_address_host_order,
                            uint16_t source_port,
                            tg_buffer* packet);
    int tg_disco_build_call_me_maybe(const tg_disco* disco,
                                     const uint8_t recipient_disco_key[32],
                                     const uint32_t* endpoint_addresses_host_order,
                                     const uint16_t* endpoint_ports,
                                     size_t endpoint_count,
                                     tg_buffer* packet);
    int tg_disco_parse(const tg_disco* disco,
                       const uint8_t* packet,
                       size_t packet_size,
                       tg_disco_message* message);

    tg_tunnel* tg_tunnel_create(const uint8_t private_key[32]);
    void tg_tunnel_destroy(tg_tunnel* tunnel);
    int tg_tunnel_add_peer(tg_tunnel* tunnel,
                           const uint8_t public_key[32],
                           const uint8_t preshared_key[32],
                           uint16_t keepalive_seconds,
                           size_t* peer_id);
    int tg_tunnel_create_handshake(tg_tunnel* tunnel, size_t peer_id, tg_buffer* packet);
    int tg_tunnel_process_packet(tg_tunnel* tunnel,
                                 size_t peer_id,
                                 const uint8_t* packet,
                                 size_t packet_size,
                                 tg_received_packet* result);
    int tg_tunnel_encrypt(tg_tunnel* tunnel,
                          size_t peer_id,
                          const uint8_t* plaintext,
                          size_t plaintext_size,
                          tg_buffer* packet);
    int tg_tunnel_has_session(tg_tunnel* tunnel, size_t peer_id);
    int tg_tunnel_update_timers(tg_tunnel* tunnel, size_t peer_id, tg_tunnel_action* action);

#ifdef __cplusplus
}
#endif
