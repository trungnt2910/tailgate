#include "Services.h"

#include <stdatomic.h>
#include <stdlib.h>

#include "Hooks.h"

static _Atomic(const struct tailgate_lwip_services*) tailgate_lwip_active_services;

static const struct tailgate_lwip_services* tailgate_lwip_require_services(void)
{
    const struct tailgate_lwip_services* services =
        atomic_load_explicit(&tailgate_lwip_active_services, memory_order_acquire);
    if (services == NULL)
    {
        abort();
    }
    return services;
}

int tailgate_lwip_acquire_services(const struct tailgate_lwip_services* services)
{
    const struct tailgate_lwip_services* expected = NULL;
    if (services == NULL || services->Now == NULL || services->Random == NULL ||
        services->InitialSequence == NULL)
    {
        return 0;
    }
    return atomic_compare_exchange_strong_explicit(&tailgate_lwip_active_services,
                                                   &expected,
                                                   services,
                                                   memory_order_acq_rel,
                                                   memory_order_acquire);
}

void tailgate_lwip_release_services(const struct tailgate_lwip_services* services)
{
    const struct tailgate_lwip_services* expected = services;
    if (!atomic_compare_exchange_strong_explicit(&tailgate_lwip_active_services,
                                                 &expected,
                                                 NULL,
                                                 memory_order_acq_rel,
                                                 memory_order_acquire))
    {
        abort();
    }
}

uint32_t sys_now(void)
{
    const struct tailgate_lwip_services* services = tailgate_lwip_require_services();
    return services->Now(services->Context);
}

uint32_t tailgate_lwip_random(void)
{
    const struct tailgate_lwip_services* services = tailgate_lwip_require_services();
    return services->Random(services->Context);
}

uint32_t tailgate_lwip_tcp_isn(const ip_addr_t* local,
                               uint16_t local_port,
                               const ip_addr_t* remote,
                               uint16_t remote_port)
{
    const struct tailgate_lwip_services* services = tailgate_lwip_require_services();
    return services->InitialSequence(services->Context, local, local_port, remote, remote_port);
}
