#pragma once

#include <stdint.h>

#include <lwip/ip_addr.h>

#ifdef __cplusplus
extern "C"
{
#endif

    struct tailgate_lwip_services
    {
        void* Context;
        uint32_t (*Now)(void* context);
        uint32_t (*Random)(void* context);
        uint32_t (*InitialSequence)(void* context,
                                    const ip_addr_t* local,
                                    uint16_t local_port,
                                    const ip_addr_t* remote,
                                    uint16_t remote_port);
    };

    // The Core runtime installs its injected providers for the duration of exclusive stack use.
    int tailgate_lwip_acquire_services(const struct tailgate_lwip_services* services);
    void tailgate_lwip_release_services(const struct tailgate_lwip_services* services);

#ifdef __cplusplus
}
#endif
