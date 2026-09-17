#pragma once

#include <stdint.h>

#include <lwip/ip_addr.h>

#ifdef __cplusplus
extern "C"
{
#endif

    uint32_t tailgate_lwip_tcp_isn(const ip_addr_t* local,
                                   uint16_t local_port,
                                   const ip_addr_t* remote,
                                   uint16_t remote_port);

#ifdef __cplusplus
}
#endif
